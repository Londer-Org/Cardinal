package httpapi

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/claims"
	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/policy"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/google/uuid"
)

// What a host is allowed to know.
//
// This is the question SSSD answers by asking LDAP, and answering it the same
// way would reproduce the failure that makes LDAP hosts dangerous: a bound host
// can enumerate the whole directory, so compromising the least important
// machine in the fleet yields every name, uid and group in the company.
//
// So the host is told about the people who may log into *it*, and nobody else.
// Cedar decides, per user, exactly as it decides certificate issuance — same
// action, same resource, same context — so a host's view of the directory and
// its actual access cannot drift apart.

type assignedUser struct {
	Name   string `json:"name"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Home   string `json:"home"`
	Shell  string `json:"shell"`
	Groups []int  `json:"groups"`

	// Sudo means Cedar permits RunAsRoot here. It rides the same response as
	// the identity record because it is answered by the same evaluation of the
	// same directory against the same host, and because an agent that fetched
	// them separately could install a sudoers file naming somebody its POSIX
	// provider does not know.
	Sudo bool `json:"sudo"`
}

type assignedGroup struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

type hostAssignment struct {
	Host        string `json:"host"`
	GeneratedAt string `json:"generatedAt"`

	Users  []assignedUser  `json:"users"`
	Groups []assignedGroup `json:"groups"`

	// Unnumbered names people who may log in but have no uid.
	//
	// The failure this prevents is silent and miserable to debug: policy says
	// yes, a certificate is issued, and sshd rejects the login because the host
	// cannot resolve the name. Nothing in that chain says why. Reporting it
	// here means the agent can log it and an operator can see it before anyone
	// tries.
	Unnumbered []string `json:"unnumbered"`
}

// handleHostAssignment answers what this host should serve.
//
// Deliberately not logged as a decision per user. Every other Cedar evaluation
// in Cardinal writes to the decision log, and this one would write one row per
// user per host per poll — tens of thousands a day for a fleet, drowning the
// log that exists so a human can find the interesting entries. The trade is
// sound because knowing a name is not access: whether alice may actually log in
// is decided again at certificate issuance, and *that* is logged.
func (s *Server) handleHostAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cred, ok := HostFrom(ctx)
	if !ok {
		writeError(w, http.StatusUnauthorized, "host authentication failed")
		return
	}

	engine := s.policy.Load()
	if engine == nil {
		// Fail closed, and loudly. An agent that received an empty assignment
		// would install it and every login on that host would stop working —
		// which is the same symptom as a correct empty answer, so it must not
		// be possible to produce one by accident.
		s.log.ErrorContext(ctx, "host assignment: no policy is active — refusing")
		writeError(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}

	hostSubject, err := s.claims.ResolveByID(ctx, cred.HostID)
	if err != nil {
		s.log.ErrorContext(ctx, "host assignment: resolving host memberships failed",
			"error", err)
		writeError(w, http.StatusServiceUnavailable, "could not resolve this host")
		return
	}

	identities, err := s.store.ListPOSIXIdentities(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "host assignment: listing POSIX identities failed",
			"error", err)
		writeError(w, http.StatusServiceUnavailable, "could not read POSIX identities")
		return
	}

	// gid by group, so a user's memberships can be projected to numbers without
	// a second pass over the list.
	gids := make(map[uuid.UUID]store.POSIXIdentity)
	for _, p := range identities {
		if p.Type == directory.TypeGroup {
			gids[p.EntityID] = p
		}
	}

	assignment := hostAssignment{
		Host:        cred.HostName,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Users:       []assignedUser{},
		Groups:      []assignedGroup{},
		Unnumbered:  []string{},
	}

	members := make(map[uuid.UUID][]string)

	// Which identities this response will contain — users, and the groups their
	// memberships project to. Both are numbers a machine is about to write down.
	serving := make(map[uuid.UUID]struct{})

	for _, p := range identities {
		if p.Type != directory.TypeUser {
			continue
		}

		subject, err := s.claims.ResolveByID(ctx, p.EntityID)
		if err != nil {
			// One unresolvable user must not cost the host its whole
			// assignment. Skipping them is the same outcome as them not being
			// permitted, which is the safe direction.
			s.log.WarnContext(ctx, "host assignment: skipping unresolvable user",
				"user", p.EntityID, "error", err)
			continue
		}

		if !s.mayLogIn(engine, subject, cred, hostSubject) {
			continue
		}

		user := assignedUser{
			Name: p.Name, UID: p.Number,
			Sudo: s.mayRunAsRoot(engine, subject, cred, hostSubject),
			// The user-private group: same name, same number, synthesised by
			// the agent rather than stored. Nothing to look up.
			GID:    p.Number,
			Home:   p.HomeDirectory,
			Shell:  p.LoginShell,
			Groups: []int{},
		}

		for _, g := range subject.Groups {
			numbered, ok := gids[g.ID]
			if !ok {
				// A directory group with no gid is invisible to the kernel.
				// Not an error: most groups exist for policy and web access and
				// have no business appearing in `id`.
				continue
			}
			user.Groups = append(user.Groups, numbered.Number)
			members[g.ID] = append(members[g.ID], p.Name)
			serving[numbered.EntityID] = struct{}{}
		}

		assignment.Users = append(assignment.Users, user)
		serving[p.EntityID] = struct{}{}
	}

	// Only the groups somebody on this host is actually in. A group nobody here
	// belongs to is one more name the host has no reason to learn.
	for id, names := range members {
		g := gids[id]
		slices.Sort(names)
		assignment.Groups = append(assignment.Groups, assignedGroup{
			Name: g.Name, GID: g.Number, Members: names,
		})
	}
	slices.SortFunc(assignment.Groups, func(a, b assignedGroup) int {
		return a.GID - b.GID
	})

	// Stamped before the response is written, and a failure here fails the
	// request. The guard on adopting a number depends on this having happened:
	// if the mark is lost, a number can be changed after a machine has already
	// put it on a filesystem, and the symptom is files belonging to the wrong
	// person weeks later. Refusing to serve is the safe direction — the agent
	// keeps whatever it last cached.
	served := make([]uuid.UUID, 0, len(assignment.Users))
	for _, p := range identities {
		if _, ok := serving[p.EntityID]; ok {
			served = append(served, p.EntityID)
		}
	}
	if err := s.store.MarkPOSIXNumbersServed(ctx, served); err != nil {
		s.log.ErrorContext(ctx, "host assignment: could not record numbers as served",
			"host", cred.HostName, "error", err)
		writeError(w, http.StatusServiceUnavailable,
			"could not record this assignment; refusing to serve numbers that "+
				"could still be changed")
		return
	}

	assignment.Unnumbered = s.permittedWithoutNumbers(
		ctx, engine, cred, hostSubject, identities)

	if len(assignment.Unnumbered) > 0 {
		s.log.WarnContext(ctx, "host assignment: permitted users have no uid",
			"host", cred.HostName, "users", assignment.Unnumbered)
	}

	writeJSON(w, http.StatusOK, assignment)
}

// mayLogIn asks the same question certificate issuance asks, of a hypothetical
// person rather than a live one.
//
// The distinction is the whole subtlety here, and getting it wrong produces a
// wrong answer that looks exactly like a right one. Policy forbids SSHLogin
// unless the principal is device-bound and recently authenticated — properties
// of a *session*, and there is no session: nobody is logging in, an agent is
// asking who might. Evaluated verbatim, every user fails that forbid and every
// host receives an empty assignment, which is indistinguishable from "nobody has
// access here" and would be installed without complaint.
//
// So the subject is evaluated as if ideally authenticated. That is safe only
// because this endpoint grants nothing: it decides which *names* a host may
// resolve, and whether anyone may actually log in is decided again at
// certificate issuance, against their real credential, and logged there.
//
// localAccount is the user's own login, because that is the account this host
// would be serving. Someone permitted only as a shared account like `deploy`
// does not appear — `deploy` is a local account the machine already has, and
// there is no directory identity for the host to resolve.
func (s *Server) mayLogIn(
	engine *policy.Engine, subject *claims.Subject,
	host *store.HostCredential, hostSubject *claims.Subject,
) bool {
	ideal := *subject
	ideal.Auth = claims.AuthContext{
		Method:      "passkey",
		At:          time.Now(),
		DeviceBound: true,
	}

	decision := engine.Evaluate(policy.Request{
		Subject:        &ideal,
		Action:         policy.ActionSSHLogin,
		Resource:       types.NewEntityUID(policy.TypeHost, types.String(host.HostID.String())),
		ResourceGroups: hostSubject.Groups,
		Context: map[string]types.Value{
			"localAccount": types.String(ideal.Login),
			"host":         types.String(host.HostName),
		},
	})
	return decision.Allowed
}

// mayRunAsRoot decides whether this person's name belongs in the sudoers file.
//
// Same as-if-authenticated substitution as mayLogIn, and here the consequence
// is sharper, so it is worth being explicit about. The policy forbids RunAsRoot
// unless the principal authenticated recently; at render time nobody has
// authenticated at all, so the rendered rule cannot carry that condition and
// the file grants passwordless root to everyone this reaches.
//
// That is not a shortcut being taken quietly — it is the shape of the problem.
// Cardinal has no passwords, so a sudoers rule demanding one would prompt for a
// credential that does not exist. What actually gates sudo is the shell: the
// only way to have one as this person is a Cardinal certificate issued minutes
// ago after a device-bound passkey. ADR 0026 states the consequence, including
// the part that does not work out neatly.
func (s *Server) mayRunAsRoot(
	engine *policy.Engine, subject *claims.Subject,
	host *store.HostCredential, hostSubject *claims.Subject,
) bool {
	ideal := *subject
	ideal.Auth = claims.AuthContext{
		Method:      "passkey",
		At:          time.Now(),
		DeviceBound: true,
	}

	return engine.Evaluate(policy.Request{
		Subject:        &ideal,
		Action:         policy.ActionRunAsRoot,
		Resource:       types.NewEntityUID(policy.TypeHost, types.String(host.HostID.String())),
		ResourceGroups: hostSubject.Groups,
		Context: map[string]types.Value{
			"host": types.String(host.HostName),
		},
	}).Allowed
}

// permittedWithoutNumbers finds people policy allows onto this host who have no
// uid to be served under.
//
// A separate pass over every user rather than a by-product of the first, because
// the first pass only ever sees people who already have numbers — which is
// exactly the set this is trying to look outside of.
func (s *Server) permittedWithoutNumbers(
	ctx context.Context, engine *policy.Engine,
	host *store.HostCredential, hostSubject *claims.Subject,
	numbered []store.POSIXIdentity,
) []string {
	hasNumber := make(map[uuid.UUID]bool, len(numbered))
	for _, p := range numbered {
		hasNumber[p.EntityID] = true
	}

	users, err := s.store.ListEntities(ctx, directory.TypeUser, false)
	if err != nil {
		s.log.WarnContext(ctx, "host assignment: could not check for unnumbered users",
			"error", err)
		return []string{}
	}

	out := []string{}
	for _, u := range users {
		if hasNumber[u.ID] {
			continue
		}
		subject, err := s.claims.ResolveByID(ctx, u.ID)
		if err != nil {
			continue
		}
		if s.mayLogIn(engine, subject, host, hostSubject) {
			out = append(out, u.Name)
		}
	}
	slices.Sort(out)
	return out
}
