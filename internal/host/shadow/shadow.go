// Package shadow compares what Cardinal would do against what the machine
// currently does, and changes nothing.
//
// It is the most important migration feature and the least glamorous. Cutting a
// host over is only safe if Cardinal and the machine agree about the things a
// mistake cannot be undone in — and there is exactly one of those. If the
// machine says alice is uid 1234 and Cardinal says 100003, then the moment
// Cardinal wins, every file alice owns belongs to a stranger and every file the
// stranger owns belongs to alice. No amount of care afterwards fixes it, because
// the filesystem recorded a number and the number is what changed.
//
// Deliberately incurious about where the machine's answer comes from. It asks
// through getent, which is the whole NSS chain — sssd against LDAP or Active
// Directory, nss_ldap, plain /etc/passwd, or something nobody here has heard of.
// Nothing in this package knows or needs to know which, and a version that
// queried a particular directory would work for one kind of deployment and be
// useless for the rest.
//
// So this reports and does not act. Strictly: no varlink socket, no sudoers
// file, no certificate. ADR 0020 already noted why that has to be absolute —
// comparing the agent's answers against the machine's is meaningless if the
// agent is already the thing answering.
package shadow

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

// Severity says what to do about a finding.
type Severity string

const (
	// Blocking means cutting over would destroy something. Today that is one
	// thing: a uid or gid that disagrees.
	Blocking Severity = "blocking"

	// Review means access changes in a way somebody should agree to before it
	// happens — usually somebody gaining or losing sudo.
	Review Severity = "review"

	// Additive means Cardinal grants something the machine does not have. Safe
	// by construction: nothing existing is disturbed.
	Additive Severity = "additive"

	// Match means the two agree.
	Match Severity = "match"
)

// Finding is one comparison.
type Finding struct {
	User     string   `json:"user"`
	Severity Severity `json:"severity"`

	// What describes the property. Kept short because it is a column heading.
	What string `json:"what"`

	Local    string `json:"local"`
	Cardinal string `json:"cardinal"`

	// Why is written for whoever has to decide, and says what happens rather
	// than what differs.
	Why string `json:"why,omitempty"`
}

// Report is everything the comparison found.
type Report struct {
	Host     string    `json:"host"`
	Findings []Finding `json:"findings"`

	// Unchecked names people the comparison could not reach a verdict on.
	//
	// Not an oversight — a limitation worth printing. Directory-backed NSS
	// providers disable enumeration by default, exactly as Cardinal does and for
	// the same reason, so there is usually no way to ask the machine "who else
	// do you know about". Somebody it can resolve and Cardinal has never heard
	// of is invisible here, and the only remedy is to name them.
	Unchecked []string `json:"unchecked,omitempty"`
}

// Blocking reports whether cutting over would destroy something.
func (r *Report) Blocking() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == Blocking {
			out = append(out, f)
		}
	}
	return out
}

// Counts summarises by severity.
func (r *Report) Counts() map[Severity]int {
	out := map[Severity]int{}
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// PosixRecord is what the machine currently believes about somebody.
type PosixRecord struct {
	UID    int
	GID    int
	Home   string
	Shell  string
	Groups []string
}

// System is the machine being compared against.
//
// An interface so the comparison can be tested without a machine wired up to a
// real directory — and so that what is being asked of the system is written down
// in one place rather than spread across shell-outs.
type System interface {
	// LookupUser returns what NSS currently answers. The second result
	// distinguishes "no such user" from a lookup that failed, because they mean
	// completely different things during a migration.
	LookupUser(ctx context.Context, name string) (PosixRecord, bool, error)

	// SudoAllowed reports whether sudo currently grants this person anything.
	SudoAllowed(ctx context.Context, name string) (bool, error)
}

// Expected is what Cardinal would install.
type Expected struct {
	Name   string
	UID    int
	GID    int
	Home   string
	Shell  string
	Groups []string
	Sudo   bool
}

// Compare produces the report.
//
// alsoCheck names people Cardinal has never heard of, which is a different
// question from the ones in expected and needs a different answer. Comparing
// them against an empty Expected would say Cardinal wants uid 0 — measured, on
// a live run, where `-users root,daemon` produced two blocking findings claiming
// root was about to be renumbered.
func Compare(
	ctx context.Context, host string, expected []Expected, alsoCheck []string,
	system System,
) (*Report, error) {
	report := &Report{Host: host}

	for _, want := range expected {
		local, found, err := system.LookupUser(ctx, want.Name)
		if err != nil {
			return nil, fmt.Errorf("shadow: looking up %s: %w", want.Name, err)
		}

		if !found {
			report.Findings = append(report.Findings, Finding{
				User: want.Name, Severity: Additive, What: "account",
				Local: "absent", Cardinal: strconv.Itoa(want.UID),
				Why: "new to this machine; nothing existing is disturbed",
			})
			// Sudo is still worth reporting for somebody new, because gaining
			// root is a decision even when the account is not.
			report.Findings = append(report.Findings,
				sudoFinding(want.Name, false, want.Sudo))
			continue
		}

		report.Findings = append(report.Findings, identityFindings(want, local)...)

		allowed, err := system.SudoAllowed(ctx, want.Name)
		if err != nil {
			return nil, fmt.Errorf("shadow: checking sudo for %s: %w", want.Name, err)
		}
		report.Findings = append(report.Findings, sudoFinding(want.Name, allowed, want.Sudo))
	}

	known := make(map[string]bool, len(expected))
	for _, want := range expected {
		known[want.Name] = true
	}

	for _, name := range alsoCheck {
		if known[name] {
			// Already compared properly above; naming somebody twice should not
			// produce a second, worse answer.
			continue
		}

		local, found, err := system.LookupUser(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("shadow: looking up %s: %w", name, err)
		}
		if !found {
			// Neither system knows them. Recorded so the operator can see the
			// name was checked rather than silently dropped.
			report.Unchecked = append(report.Unchecked, name)
			continue
		}

		report.Findings = append(report.Findings, Finding{
			User: name, Severity: Review, What: "unknown to Cardinal",
			Local: strconv.Itoa(local.UID), Cardinal: "absent",
			Why: "exists on this machine and Cardinal has no record; " +
				"if this is a directory account it stops resolving on cutover, " +
				"and if it is a local one nothing changes",
		})
	}

	return report, nil
}

// identityFindings compares the numbers and the paths.
//
// The uid comparison is the only Blocking one in the whole package, and it is
// what this exists for. Everything else here is a change somebody can undo.
func identityFindings(want Expected, local PosixRecord) []Finding {
	out := []Finding{{
		User: want.Name, What: "uid",
		Local: strconv.Itoa(local.UID), Cardinal: strconv.Itoa(want.UID),
	}}

	if local.UID == want.UID {
		out[0].Severity = Match
	} else {
		out[0].Severity = Blocking
		out[0].Why = fmt.Sprintf(
			"every file owned by uid %d becomes %s's, and every file %s owns "+
				"becomes uid %d's — the filesystem recorded the number",
			want.UID, want.Name, want.Name, local.UID)
	}

	gid := Finding{
		User: want.Name, What: "gid",
		Local: strconv.Itoa(local.GID), Cardinal: strconv.Itoa(want.GID),
		Severity: Match,
	}
	if local.GID != want.GID {
		gid.Severity = Blocking
		gid.Why = "group ownership of every file this account created changes"
	}
	out = append(out, gid)

	// The home directory is a rename at worst: the files are still there and
	// still owned by the same uid, and somebody logs into an empty directory
	// until it is moved. Worth agreeing to, not worth blocking on.
	if local.Home != want.Home {
		out = append(out, Finding{
			User: want.Name, Severity: Review, What: "home",
			Local: local.Home, Cardinal: want.Home,
			Why: "logins land somewhere new; the old directory is untouched",
		})
	}
	if local.Shell != want.Shell {
		out = append(out, Finding{
			User: want.Name, Severity: Review, What: "shell",
			Local: local.Shell, Cardinal: want.Shell,
		})
	}

	lost, gained := groupDifference(local.Groups, want.Groups)
	if len(lost) > 0 {
		out = append(out, Finding{
			User: want.Name, Severity: Review, What: "groups lost",
			Local: strings.Join(lost, ","), Cardinal: "—",
			Why: "anything granted by these groups stops applying on cutover",
		})
	}
	if len(gained) > 0 {
		out = append(out, Finding{
			User: want.Name, Severity: Additive, What: "groups gained",
			Local: "—", Cardinal: strings.Join(gained, ","),
		})
	}

	return out
}

func sudoFinding(name string, local, cardinal bool) Finding {
	f := Finding{
		User: name, What: "sudo",
		Local: yesNo(local), Cardinal: yesNo(cardinal),
	}
	switch {
	case local == cardinal:
		f.Severity = Match
	case cardinal:
		f.Severity = Review
		f.Why = "gains root on this machine"
	default:
		f.Severity = Review
		f.Why = "loses root on this machine"
	}
	return f
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// groupDifference ignores the user-private group.
//
// Every machine has one and its name is the login, so reporting it as a change
// would put a line in every report that never means anything — which is how a
// report stops being read.
func groupDifference(local, cardinal []string) (lost, gained []string) {
	for _, g := range local {
		if !slices.Contains(cardinal, g) {
			lost = append(lost, g)
		}
	}
	for _, g := range cardinal {
		if !slices.Contains(local, g) {
			gained = append(gained, g)
		}
	}
	return lost, gained
}

// Local asks the machine itself.
//
// Through getent and sudo rather than through Go's os/user, which reads
// /etc/passwd directly when cgo is disabled — and would therefore report that
// nobody served by a directory exists at all, turning every comparison into a
// false "additive" and making the whole exercise say the migration is safe.
type Local struct{}

// LookupUser runs getent, which is the whole NSS chain and not a file.
func (Local) LookupUser(ctx context.Context, name string) (PosixRecord, bool, error) {
	line, found, err := run(ctx, "getent", "passwd", name)
	if err != nil || !found {
		return PosixRecord{}, false, err
	}

	// name:password:uid:gid:gecos:home:shell
	fields := strings.Split(strings.TrimSpace(line), ":")
	if len(fields) < 7 {
		return PosixRecord{}, false, fmt.Errorf("shadow: getent returned %q", line)
	}

	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		return PosixRecord{}, false, fmt.Errorf("shadow: uid %q is not a number", fields[2])
	}
	gid, err := strconv.Atoi(fields[3])
	if err != nil {
		return PosixRecord{}, false, fmt.Errorf("shadow: gid %q is not a number", fields[3])
	}

	record := PosixRecord{UID: uid, GID: gid, Home: fields[5], Shell: fields[6]}

	groups, _, err := run(ctx, "id", "-nG", name)
	if err != nil {
		return PosixRecord{}, false, err
	}
	for _, g := range strings.Fields(groups) {
		// The user-private group is not a membership, it is the passwd record's
		// gid rendered by name. Dropped so the comparison is about real groups.
		if g != name {
			record.Groups = append(record.Groups, g)
		}
	}

	return record, true, nil
}

// SudoAllowed asks sudo what it would do.
//
// By reading the output rather than the exit status, because `sudo -l -U`
// exits 0 whether or not the person has any privilege — measured, not assumed.
// Only a genuinely unknown user makes it exit non-zero.
func (Local) SudoAllowed(ctx context.Context, name string) (bool, error) {
	out, found, err := run(ctx, "sudo", "-l", "-U", name)
	if err != nil || !found {
		return false, err
	}
	return strings.Contains(out, "may run the following commands"), nil
}

// run executes a command with a forced C locale.
//
// The locale matters and is easy to miss: sudo translates "may run the
// following commands", so on a machine set to French the check above would
// quietly report that nobody has sudo — a migration report that says everything
// matches when nothing was compared.
func run(ctx context.Context, name string, args ...string) (output string, found bool, err error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", false, fmt.Errorf("shadow: %s is not installed, so there is "+
			"nothing to compare against: %w", name, err)
	}

	//nolint:gosec // the command comes from LookPath and the arguments are ours
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")

	raw, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			// A non-zero exit is "no such user" for both getent and sudo, and
			// that is a finding rather than a failure.
			return "", false, nil
		}
		return "", false, fmt.Errorf("shadow: running %s: %w", name, err)
	}
	return string(raw), true, nil
}
