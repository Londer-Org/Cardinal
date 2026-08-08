// Package sudoers renders and installs the drop-in file granting sudo.
//
// Everything here is arranged so that a bad render cannot become the file that
// is live. What a broken file actually costs was measured rather than assumed,
// because the received wisdom is wrong: sudo 1.9 does *not* refuse to run when
// a drop-in fails to parse. It reports the error, skips that file, and carries
// on — so root keeps working and the machine is not bricked.
//
// The real cost is smaller and still worth preventing:
//
//   - Everyone named only in the broken file silently loses sudo. Silent
//     removal of access is the failure mode this project exists to make
//     impossible elsewhere; producing it here would be poor.
//   - Every sudo invocation on the machine prints a syntax error, on every
//     terminal, to everybody. That reads as a compromised system.
//   - `visudo -c` exits non-zero for the whole configuration afterwards, so
//     every other tool that checks it starts failing too.
//
// So the rules are absolute rather than best-effort:
//
//   - Nothing is installed that `visudo -c` has not accepted.
//   - If visudo cannot be run, nothing is installed. Writing a file nobody has
//     checked is how the above happens.
//   - Only Cardinal's own drop-in is ever written. /etc/sudoers is never
//     touched and no other file in sudoers.d is read, moved or removed, so the
//     agent is structurally incapable of taking away local root.
package sudoers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// DefaultPath is the drop-in Cardinal owns.
//
// No extension: sudo ignores any file in sudoers.d whose name contains a dot or
// ends in a tilde, so `50-cardinal.conf` would be silently skipped and the
// symptom would be sudo quietly not working. The numeric prefix orders it after
// a distribution's own defaults and before anything an administrator adds late.
const DefaultPath = "/etc/sudoers.d/50-cardinal"

// safeUserName is deliberately stricter than POSIX allows.
//
// A sudoers file is line-oriented and unquoted, so a name containing a space, a
// newline or a comma is not merely unrenderable — it is an injection. The
// directory does not constrain names to this alphabet, which is why this is
// checked here rather than assumed.
var safeUserName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ErrUnsafeName means a directory name cannot be written into a sudoers file.
var ErrUnsafeName = errors.New("sudoers: name cannot be safely rendered")

// ErrNoValidator means visudo is absent.
var ErrNoValidator = errors.New("sudoers: visudo is not available")

// Render produces the drop-in for the given logins.
//
// Refuses outright if any name is unsafe, rather than skipping it. Skipping
// would silently remove somebody's sudo, and an unrenderable name means either
// a bug upstream or somebody trying something — neither is a case for carrying
// on with a partial file.
func Render(logins []string, host string, generated time.Time) ([]byte, error) {
	sorted := slices.Clone(logins)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)

	for _, login := range sorted {
		if !safeUserName.MatchString(login) {
			return nil, fmt.Errorf("%w: %q", ErrUnsafeName, login)
		}
	}

	var out bytes.Buffer
	fmt.Fprintf(&out, `# Managed by Cardinal. Every edit here is discarded on the next refresh.
#
# host       %s
# generated  %s
#
# NOPASSWD, necessarily: Cardinal has no passwords, so a rule demanding one
# would prompt for a credential that cannot exist. What gates sudo is the shell
# itself — the only way to have one as these people is a Cardinal certificate
# issued after a device-bound passkey. See docs/adr/0026.
#
# Local root is untouched. This file only ever adds; nothing Cardinal does can
# remove an account's existing access, and /etc/sudoers is never edited.

`, host, generated.UTC().Format(time.RFC3339))

	if len(sorted) == 0 {
		// A comment rather than an empty file, because "nobody may sudo here"
		// and "the agent has never run" look identical otherwise, and the two
		// call for completely different responses.
		out.WriteString("# Nobody in the directory may run as root on this host.\n")
		return out.Bytes(), nil
	}

	for _, login := range sorted {
		fmt.Fprintf(&out, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n", login)
	}
	return out.Bytes(), nil
}

// Install validates and writes the drop-in atomically.
//
// `visudo -c` runs against the candidate before anything is moved into place, so
// a refusal leaves whatever was there before. Keeping the previous file is the
// right failure: it means access somebody already had is not withdrawn by a bug
// in the renderer.
func Install(ctx context.Context, path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("sudoers: creating %s: %w", dir, err)
	}

	// The temp file goes in the same directory so the rename is atomic rather
	// than a copy across filesystems — and is prefixed with a dot so that if
	// this process dies between creating and removing it, sudo ignores the
	// leftover instead of parsing a half-written file.
	tmp, err := os.CreateTemp(dir, ".cardinal-*")
	if err != nil {
		return fmt.Errorf("sudoers: creating candidate: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() //nolint:errcheck // cleanup of a file that the success path has already renamed away

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close() //nolint:errcheck // best effort; the meaningful error is the one being returned
		return fmt.Errorf("sudoers: writing candidate: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() //nolint:errcheck // best effort; the meaningful error is the one being returned
		return fmt.Errorf("sudoers: syncing candidate: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("sudoers: closing candidate: %w", err)
	}

	// 0440, which is what visudo itself creates and what every distribution
	// ships. sudo refuses to read a file anyone but its owner can write and
	// reports it as a syntax problem, so this has to be right before visudo sees
	// it or the validation fails for a reason that reads as unrelated.
	if err := os.Chmod(tmp.Name(), 0o440); err != nil { //nolint:gosec // see above
		return fmt.Errorf("sudoers: setting candidate permissions: %w", err)
	}

	if err := Validate(ctx, tmp.Name()); err != nil {
		return err
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("sudoers: installing %s: %w", path, err)
	}
	return nil
}

// Validate runs visudo against a candidate file.
//
// Takes a context because visudo is another process: an agent that blocked
// forever on a wedged one would stop refreshing identity as well, and the
// symptom would be a host silently falling behind rather than an error.
func Validate(ctx context.Context, path string) error {
	visudo, err := exec.LookPath("visudo")
	if err != nil {
		// Not a warning to carry on past. A host without visudo is a host where
		// the check cannot be made, and installing anyway would be choosing to
		// find out from the people whose sudo stopped working.
		return fmt.Errorf("%w: refusing to install an unchecked sudoers file", ErrNoValidator)
	}

	//nolint:gosec // visudo comes from LookPath and the path is one we just wrote
	cmd := exec.CommandContext(ctx, visudo, "-c", "-f", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sudoers: visudo rejected the file, so it was not installed: %w\n%s",
			err, strings.TrimSpace(string(output)))
	}
	return nil
}

// IncludeDirConfigured reports whether /etc/sudoers actually reads the drop-in
// directory.
//
// Worth checking and worth not fixing. A file in sudoers.d that nothing
// includes is silently inert, and an agent reporting success while granting
// nobody anything is a bad way to spend an afternoon — but editing /etc/sudoers
// to repair it would break the rule that makes this package safe. Report, and
// let a human decide.
func IncludeDirConfigured(sudoersPath, dropInDir string) (bool, error) {
	raw, err := os.ReadFile(sudoersPath) //nolint:gosec // a fixed system path
	if err != nil {
		return false, fmt.Errorf("sudoers: reading %s: %w", sudoersPath, err)
	}

	for line := range strings.Lines(string(raw)) {
		line = strings.TrimSpace(line)
		// Both spellings: @includedir is the modern one and #includedir is what
		// every distribution still ships. The second looks like a comment and
		// is not, which is exactly why a check that only understood one would
		// report a working system as broken.
		for _, directive := range []string{"@includedir", "#includedir"} {
			if rest, ok := strings.CutPrefix(line, directive); ok {
				if strings.TrimSpace(rest) == dropInDir {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
