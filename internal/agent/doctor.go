package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/arthur-lonfils/cardinal/internal/sudoers"
	"github.com/arthur-lonfils/cardinal/internal/userdb"
)

// Checking a machine is ready, rather than making it ready.
//
// The package installs a binary, a unit and a config file, and stops there. It
// does not add `systemd` to nsswitch.conf or `@includedir` to /etc/sudoers, even
// though both are needed and both have precedent — libnss-systemd's own postinst
// edits nsswitch.conf.
//
// The reason is what Cardinal is. A package that silently reorders how a machine
// resolves every username, as a side effect of an install somebody did to "have
// a look", is exactly the surprise that makes people distrust an identity
// system. The agent follows the same rule for the same reason, and it would be
// odd for the package to be allowed what the daemon is not.
//
// So: report precisely, with the command to fix each thing, and let a human run
// it.

// Check is one prerequisite and what was found.
type Check struct {
	Name string

	// OK is false when something needs doing. Advice is then non-empty.
	OK bool

	// Detail is what was found, phrased so it is useful when OK is true as well
	// — a report where the passing lines say nothing is a report people skim.
	Detail string

	// Advice is the command or edit that fixes it.
	Advice string

	// Fatal marks a check whose failure means the agent cannot work at all, as
	// opposed to one that limits what it can do.
	Fatal bool
}

// Diagnose examines the machine.
//
// Deliberately reads only. It is run by an operator wondering why something is
// not working, and a diagnostic that changes things is one you cannot run twice
// to see whether the change helped.
func Diagnose(ctx context.Context, cfg *Config) []Check {
	candidates := []Check{
		enrolled(cfg),
		nsswitchReady(cfg),
		userdbSocket(cfg),
		sudoersIncluded(cfg),
		visudoPresent(),
		sshdDropInSupported(ctx, cfg),
	}

	// An empty Name means the check did not apply — that part of the agent is
	// switched off in configuration, and reporting on it would be noise.
	out := make([]Check, 0, len(candidates))
	for _, c := range candidates {
		if c.Name != "" {
			out = append(out, c)
		}
	}
	return out
}

// Ready reports whether nothing fatal is outstanding.
func Ready(checks []Check) bool {
	for _, c := range checks {
		if c.Fatal && !c.OK {
			return false
		}
	}
	return true
}

func enrolled(cfg *Config) Check {
	c := Check{Name: "enrolled", Fatal: true}

	if _, err := os.Stat(cfg.KeyPath); err != nil {
		c.Detail = "no key at " + cfg.KeyPath
		c.Advice = "on a workstation:  cardinal host enroll <name>\n" +
			"    then here:         cardinal-agent enroll -server " + cfg.Server + " -token <token>"
		return c
	}
	c.OK = true
	c.Detail = cfg.KeyPath
	return c
}

// nsswitchReady is the one that decides whether identity works at all.
//
// Without `systemd` in the passwd and group lines nothing consults the agent's
// socket, every lookup falls through as though Cardinal were not installed, and
// the symptom is indistinguishable from the agent being broken.
func nsswitchReady(cfg *Config) Check {
	if cfg.SocketDir == "" {
		return Check{}
	}
	c := Check{Name: "nsswitch", Fatal: true}

	raw, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		c.Detail = "could not read /etc/nsswitch.conf: " + err.Error()
		return c
	}

	missing := make([]string, 0, 2)
	for _, database := range []string{"passwd", "group"} {
		if !nsswitchNames(string(raw), database, "systemd") {
			missing = append(missing, database)
		}
	}
	if len(missing) == 0 {
		c.OK = true
		c.Detail = "passwd and group consult systemd"
		return c
	}

	c.Detail = strings.Join(missing, " and ") + " does not consult systemd"
	c.Advice = "add `systemd` to those lines in /etc/nsswitch.conf:\n" +
		"      passwd: files systemd\n" +
		"      group:  files systemd\n" +
		"    Ordering is a migration decision rather than a detail — whichever\n" +
		"    source comes first wins for a name they both know, so put systemd\n" +
		"    after any directory you are still cutting over from."
	return c
}

// nsswitchNames reports whether a database line lists a source.
func nsswitchNames(conf, database, source string) bool {
	for line := range strings.Lines(conf) {
		line = strings.TrimSpace(line)
		before, ok := strings.CutPrefix(line, database+":")
		if !ok {
			continue
		}
		// Trailing comments are not sources, and fields rather than a substring
		// search so that `sss` never satisfies a look for `s`.
		if comment := strings.IndexByte(before, '#'); comment >= 0 {
			before = before[:comment]
		}
		for _, field := range strings.Fields(before) {
			if field == source {
				return true
			}
		}
	}
	return false
}

func userdbSocket(cfg *Config) Check {
	if cfg.SocketDir == "" {
		return Check{}
	}
	c := Check{Name: "userdb socket"}

	path := userdb.SocketPath(cfg.SocketDir, userdb.ServiceName)
	if _, err := os.Stat(path); err != nil {
		c.Detail = "nothing listening at " + path
		c.Advice = "systemctl start cardinal-agent"
		return c
	}
	c.OK = true
	c.Detail = path
	return c
}

// sudoersIncluded catches the drop-in that nothing reads.
//
// A rendered file in a directory /etc/sudoers does not include is silently
// inert: the agent reports success and grants nobody anything.
func sudoersIncluded(cfg *Config) Check {
	if cfg.SudoersPath == "" {
		return Check{}
	}
	c := Check{Name: "sudoers include"}

	dir := filepath.Dir(cfg.SudoersPath)
	included, err := sudoers.IncludeDirConfigured("/etc/sudoers", dir)
	if err != nil {
		c.Detail = err.Error()
		return c
	}
	if !included {
		c.Detail = "/etc/sudoers does not read " + dir
		c.Advice = "run `visudo` and add:  @includedir " + dir + "\n" +
			"    Cardinal will not make this edit itself — it may add a fact about\n" +
			"    this machine, and may not change how the machine authenticates people."
		return c
	}
	c.OK = true
	c.Detail = dir + " is included"
	return c
}

func visudoPresent() Check {
	c := Check{Name: "visudo"}
	if _, err := exec.LookPath("visudo"); err != nil {
		c.Detail = "not installed"
		c.Advice = "install sudo. Without visudo the agent installs no sudoers file\n" +
			"    at all, because it will not write one it could not check first."
		return c
	}
	c.OK = true
	c.Detail = "available"
	return c
}

// sshdDropInSupported catches an sshd that ignores the drop-in directory.
func sshdDropInSupported(ctx context.Context, cfg *Config) Check {
	if cfg.SSHDConfigPath == "" {
		return Check{}
	}
	c := Check{Name: "sshd drop-in"}

	sshd, found := lookSSHD()
	if !found {
		c.OK = true
		c.Detail = "sshd is not installed; nothing to configure"
		return c
	}

	dir := filepath.Dir(cfg.SSHDConfigPath)
	raw, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		c.Detail = "could not read /etc/ssh/sshd_config: " + err.Error()
		return c
	}
	if !includesDropIn(string(raw), dir) {
		c.Detail = "/etc/ssh/sshd_config does not include " + dir
		c.Advice = "add near the top of /etc/ssh/sshd_config:\n" +
			"      Include " + dir + "/*.conf\n" +
			"    Cardinal will not make this edit: sshd_config decides how this\n" +
			"    machine authenticates people."
		return c
	}

	//nolint:gosec // sshd came from lookSSHD and the argument is fixed
	if out, err := exec.CommandContext(ctx, sshd, "-t").CombinedOutput(); err != nil {
		c.Detail = "sshd -t rejects the current configuration"
		c.Advice = strings.TrimSpace(string(out))
		return c
	}

	c.OK = true
	c.Detail = dir + " is included and sshd accepts the configuration"
	return c
}

func includesDropIn(conf, dir string) bool {
	for line := range strings.Lines(conf) {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "Include ")
		if !ok {
			continue
		}
		// Matching the directory rather than an exact line, because the glob is
		// spelled differently on different distributions and only the directory
		// being reached matters.
		if strings.Contains(rest, dir) {
			return true
		}
	}
	return false
}

// ErrNotReady means at least one fatal check failed.
var ErrNotReady = errors.New("agent: this machine is not ready")

// Describe renders a check for a terminal.
func (c Check) Describe() string {
	mark := "✓"
	if !c.OK {
		mark = "✗"
	}
	return fmt.Sprintf("  %s  %-16s %s", mark, c.Name, c.Detail)
}
