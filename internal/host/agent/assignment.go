// Package agent is the host side of Cardinal: it fetches what this machine
// should know, keeps it on disk, and serves it to the system.
//
// The design constraint that shapes everything here is availability. SSSD
// caches, and if Cardinal is worse at surviving an outage than the thing it
// replaces, the project fails on its own terms — a directory that takes the
// fleet down with it is worse than three directories that do not.
//
// So: the cache is authoritative for answering, the network is only how it gets
// updated, and nothing in the serving path can block on Cardinal being
// reachable.
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"go.londer.be/cardinal/internal/host/userdb"
)

// Assignment is what Cardinal says this host should serve.
//
// The wire shape, kept deliberately close to the JSON: this struct is written
// to disk verbatim, so a field renamed on the server and not here shows up as a
// missing value rather than a parse error, and a cache written by an older
// agent still loads.
type Assignment struct {
	Host        string `json:"host"`
	GeneratedAt string `json:"generatedAt"`

	Users  []AssignedUser  `json:"users"`
	Groups []AssignedGroup `json:"groups"`

	// Unnumbered are people permitted onto this host with no uid. Carried into
	// the cache so `cardinal-agent status` can say so — it is the explanation
	// for a login that policy allowed and the machine then refused.
	Unnumbered []string `json:"unnumbered"`

	// TrustedUserCAKeys are the authorities whose user certificates this host
	// should accept, in authorized_keys format.
	//
	// Empty and absent are indistinguishable here — an older server omits the
	// field, a server with no authority configured sends none, and both decode
	// to nil. So the agent writes the trust file only when at least one key
	// arrives, and otherwise leaves whatever is on disk alone.
	//
	// That asymmetry is deliberate rather than a limitation worked around. A
	// fleet upgraded agent-first would have every host managed by a server that
	// cannot send this yet, and an agent that deleted the file on an empty
	// answer would remove trust an operator installed by hand — which is the
	// agent changing how the machine authenticates people, the one thing it may
	// not do. Withdrawing a compromised authority is a rotation, and a rotation
	// sends a non-empty list.
	TrustedUserCAKeys []string `json:"trustedUserCaKeys"`

	// FetchedAt is stamped locally, not by the server. What matters when
	// deciding whether to trust a cache is how long *this machine* has been
	// out of contact, and a server timestamp answers a different question and
	// depends on two clocks agreeing.
	FetchedAt time.Time `json:"fetchedAt"`
}

// AssignedUser is one person's POSIX record.
type AssignedUser struct {
	Name   string `json:"name"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Home   string `json:"home"`
	Shell  string `json:"shell"`
	Groups []int  `json:"groups"`

	// Sudo means Cedar permits RunAsRoot on this host.
	Sudo bool `json:"sudo"`
}

// AssignedGroup is one directory group with a gid.
type AssignedGroup struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

// Age is how long since this was fetched.
func (a *Assignment) Age() time.Duration { return time.Since(a.FetchedAt) }

// Sudoers returns the logins that may run as root here.
func (a *Assignment) Sudoers() []string {
	out := []string{}
	for _, u := range a.Users {
		if u.Sudo {
			out = append(out, u.Name)
		}
	}
	return out
}

// Snapshot is an Assignment indexed for lookup, and is what the varlink
// provider reads.
//
// Built once per refresh rather than searched per request: `ls -l` on a
// directory of a thousand files is a thousand uid lookups, and a linear scan
// per lookup would make an ordinary command visibly slow.
type Snapshot struct {
	usersByName map[string]userdb.UserRecord
	usersByUID  map[int]userdb.UserRecord

	groupsByName map[string]userdb.GroupRecord
	groupsByGID  map[int]userdb.GroupRecord

	memberships []userdb.Membership
}

// NewSnapshot indexes an assignment.
func NewSnapshot(a *Assignment) *Snapshot {
	s := &Snapshot{
		usersByName:  make(map[string]userdb.UserRecord, len(a.Users)),
		usersByUID:   make(map[int]userdb.UserRecord, len(a.Users)),
		groupsByName: make(map[string]userdb.GroupRecord, len(a.Groups)),
		groupsByGID:  make(map[int]userdb.GroupRecord, len(a.Groups)),
	}

	for _, g := range a.Groups {
		record := userdb.GroupRecord{
			GroupName: g.Name, GID: g.GID, Members: g.Members,
		}
		s.groupsByName[g.Name] = record
		s.groupsByGID[g.GID] = record

		for _, member := range g.Members {
			s.memberships = append(s.memberships,
				userdb.Membership{UserName: member, GroupName: g.Name})
		}
	}

	for _, u := range a.Users {
		record := userdb.UserRecord{
			UserName: u.Name, UID: u.UID, GID: u.GID,
			HomeDirectory: u.Home, Shell: u.Shell,
		}
		s.usersByName[u.Name] = record
		s.usersByUID[u.UID] = record

		// The user-private group, synthesised rather than stored: same name,
		// same number. Cardinal does not send it because there is nothing to
		// send — the convention *is* the record. Registered so that `getent
		// group alice` answers and `ls -l` renders the group column.
		if _, taken := s.groupsByGID[u.GID]; !taken {
			private := userdb.GroupRecord{GroupName: u.Name, GID: u.GID}
			s.groupsByName[u.Name] = private
			s.groupsByGID[u.GID] = private
		}
	}

	return s
}

// UserByName finds a cached user by login name.
func (s *Snapshot) UserByName(name string) (userdb.UserRecord, bool) {
	r, ok := s.usersByName[name]
	return r, ok
}

// UserByUID finds a cached user by its numeric uid.
func (s *Snapshot) UserByUID(uid int) (userdb.UserRecord, bool) {
	r, ok := s.usersByUID[uid]
	return r, ok
}

// GroupByName finds a cached group by name.
func (s *Snapshot) GroupByName(name string) (userdb.GroupRecord, bool) {
	r, ok := s.groupsByName[name]
	return r, ok
}

// GroupByGID finds a cached group by its numeric gid.
func (s *Snapshot) GroupByGID(gid int) (userdb.GroupRecord, bool) {
	r, ok := s.groupsByGID[gid]
	return r, ok
}

// MembershipsOf filters by user, by group, or by both.
func (s *Snapshot) MembershipsOf(userName, groupName string) []userdb.Membership {
	out := make([]userdb.Membership, 0, 4)
	for _, m := range s.memberships {
		if userName != "" && m.UserName != userName {
			continue
		}
		if groupName != "" && m.GroupName != groupName {
			continue
		}
		out = append(out, m)
	}
	return out
}

// Users returns the record names, sorted. For status output only.
func (s *Snapshot) Users() []string {
	out := make([]string, 0, len(s.usersByName))
	for name := range s.usersByName {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// DefaultCachePath is where the assignment lives between runs.
//
// Under /var/lib rather than /run, and that is the entire offline story: /run
// is a tmpfs, so a cache there would be empty after a reboot and the machine
// would come up unable to resolve anybody until Cardinal answered. A host
// rebooting during an outage is precisely when this has to work.
const DefaultCachePath = "/var/lib/cardinal/assignment.json"

// Save writes the assignment atomically.
//
// Temp file, fsync, rename — because the alternative is a truncated JSON file
// left by a power cut, and the agent would then start with no identities at all
// while believing it had a cache.
func Save(path string, a *Assignment) error {
	// 0755: the directory holds no secret, and a traversable path makes the
	// cache readable for debugging by whoever is looking at a broken host.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // see above
		return fmt.Errorf("agent: creating cache directory: %w", err)
	}

	encoded, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encoding assignment: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".assignment-*")
	if err != nil {
		return fmt.Errorf("agent: creating temporary cache: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() //nolint:errcheck // cleanup of a file the success path has already renamed away

	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close() //nolint:errcheck // best effort; the meaningful error is the one being returned
		return fmt.Errorf("agent: writing cache: %w", err)
	}
	// Before the rename, not after. A rename is atomic with respect to
	// visibility and says nothing about the data having reached the disk.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() //nolint:errcheck // best effort; the meaningful error is the one being returned
		return fmt.Errorf("agent: syncing cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agent: closing cache: %w", err)
	}

	// World-readable. It holds names, uids and home directories — the same
	// things `getent passwd` hands to any process that asks, so making the file
	// private would protect nothing while making it harder to debug.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { //nolint:gosec // world-readable on purpose; see above
		return fmt.Errorf("agent: setting cache permissions: %w", err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("agent: replacing cache: %w", err)
	}
	return nil
}

// Load reads a cached assignment.
func Load(path string) (*Assignment, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is ours or the operator's
	if err != nil {
		return nil, fmt.Errorf("agent: reading cache: %w", err)
	}

	var a Assignment
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("agent: parsing cache %s: %w", path, err)
	}
	return &a, nil
}
