package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Trusting the authority that signs user certificates.
//
// This is what makes `cardinal ssh` work at all: sshd accepts a certificate
// only if TrustedUserCAKeys names the authority that signed it. Until 0.3.0
// putting that file on a machine was a manual operator step, which made
// rotating the authority a manual fleet-wide operation — the kind nobody
// performs, so in practice the first key was the only key and the rotation
// machinery on the server side had nothing to converge on.
//
// The keys ride the assignment the agent already polls, so a rotation reaches
// every host on the ordinary interval with no additional moving part.

// DefaultUserCAPath is where the trusted authorities are written.
//
// Its own file rather than lines inside the sshd drop-in, because
// TrustedUserCAKeys takes a path and because a file the agent overwrites
// wholesale is easier to reason about than a directive somebody might also have
// set elsewhere.
const DefaultUserCAPath = "/etc/ssh/cardinal_user_ca.pub"

// InstallUserCAKeys installs the authorities this host should trust.
//
// Exported so tools/hostcheck can exercise the real writer against a real sshd
// rather than a file written to please it. That distinction has mattered here
// before: the format check in this function passes on a file `sshd -t` also
// accepts, so the only thing that proves trust *works* is a certificate login.
func (a *Agent) InstallUserCAKeys(keys []string) (bool, error) {
	return a.writeUserCAKeys(keys)
}

// writeUserCAKeys installs the authorities this host should trust.
//
// Nothing is written when the list is empty, and the existing file is left
// alone. An older server omits the field entirely and a server with no
// authority sends none, and those decode identically — so an agent that deleted
// the file on an empty answer would remove trust an operator installed by hand
// during an agent-first upgrade. That is the agent changing how the machine
// authenticates people, which is the one thing it may not do. Withdrawing a
// compromised authority is a rotation, and a rotation sends a non-empty list.
func (a *Agent) writeUserCAKeys(keys []string) (bool, error) {
	if a.UserCAPath == "" || len(keys) == 0 {
		return false, nil
	}

	// Parsed before anything is written, and this is the only check there is.
	// Measured against OpenSSH on Debian trixie: `sshd -t` accepts a
	// TrustedUserCAKeys file containing the line `not a key at all` without
	// complaint, so the usual safety net — validate the config, refuse if the
	// daemon does — does not catch this one. Whatever sshd then does with the
	// line at authentication time, it is not something to find out on a host
	// nobody can log into.
	var b strings.Builder
	b.WriteString("# Managed by Cardinal. Edits are discarded on the next refresh.\n")
	b.WriteString("#\n")
	b.WriteString("# Authorities whose user certificates this host accepts. Retired keys stay\n")
	b.WriteString("# here until their grace period ends, so a certificate issued moments\n")
	b.WriteString("# before a rotation is still honoured.\n")
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key)); err != nil {
			return false, fmt.Errorf(
				"agent: refusing to install a trusted-CA file containing a line "+
					"sshd would reject: %w", err)
		}
		b.WriteString(key)
		b.WriteString("\n")
	}

	content := b.String()

	// Unchanged is the common case — this runs on every refresh, and the
	// authority changes about once a year. Skipping the write keeps the file's
	// mtime meaningful: it becomes the answer to "when did trust last change
	// here", which is the question asked during an incident.
	if existing, err := os.ReadFile(a.UserCAPath); err == nil && string(existing) == content {
		return false, nil
	}

	dir := filepath.Dir(a.UserCAPath)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // sshd's own directory mode
		return false, fmt.Errorf("agent: creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".cardinal-ca-*.pub")
	if err != nil {
		return false, fmt.Errorf("agent: creating the trusted-CA candidate: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() //nolint:errcheck // cleanup of a file the success path has already renamed away

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close() //nolint:errcheck // best effort; the meaningful error is the one being returned
		return false, fmt.Errorf("agent: writing the trusted-CA file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("agent: closing the trusted-CA file: %w", err)
	}
	// World-readable: sshd reads it, and these are public keys.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { //nolint:gosec // public keys, read by sshd
		return false, fmt.Errorf("agent: setting the trusted-CA permissions: %w", err)
	}

	// Renamed into place, so sshd never reads a half-written file. The drop-in
	// naming it is written afterwards and validated with `sshd -t`, which is
	// what catches a path that does not resolve.
	if err := os.Rename(tmp.Name(), a.UserCAPath); err != nil {
		return false, fmt.Errorf("agent: installing the trusted-CA file: %w", err)
	}
	return true, nil
}

// TrustedUserCAKeys reports the authorities currently installed on this host.
//
// Read from disk rather than from the last assignment, because what sshd
// honours is the file — and `cardinal-agent status` exists to say what the
// machine will actually do, not what the agent last intended.
func (a *Agent) TrustedUserCAKeys() ([]string, error) {
	if a.UserCAPath == "" {
		return nil, nil
	}
	body, err := os.ReadFile(a.UserCAPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("agent: reading %s: %w", a.UserCAPath, err)
	}

	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}
