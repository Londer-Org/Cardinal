package agent_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/agent"
)

// TestConfigNeedsOnlyAServer.
//
// The smallest file that does anything is one line. A format whose minimum
// viable example is thirty lines is one people copy from a blog post without
// reading it.
func TestConfigNeedsOnlyAServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.WriteFile(path, []byte(`server = "https://id.example"`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := agent.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "https://id.example" {
		t.Fatalf("server is %q", cfg.Server)
	}
	if time.Duration(cfg.Interval) != agent.DefaultInterval {
		t.Fatalf("interval defaulted to %s", time.Duration(cfg.Interval))
	}
	if cfg.CachePath != agent.DefaultCachePath || cfg.SudoersPath == "" {
		t.Fatalf("defaults were not applied: %+v", cfg)
	}
}

// TestAConfigWithNoServerIsRefused.
//
// The one setting with no sensible default. An agent that started and silently
// did nothing would be worse than one that will not start — the second is
// noticed in seconds, the first when somebody cannot log in.
func TestAConfigWithNoServerIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.WriteFile(path, []byte(`interval = "1m"`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := agent.LoadConfig(path); err == nil {
		t.Fatal("a config with no server was accepted")
	}
}

// TestAMissingConfigSaysWhatToWrite.
func TestAMissingConfigSaysWhatToWrite(t *testing.T) {
	_, err := agent.LoadConfig(filepath.Join(t.TempDir(), "absent.toml"))
	if err == nil {
		t.Fatal("a missing config was accepted")
	}
	if !strings.Contains(err.Error(), "server =") {
		t.Fatalf("the error does not show what to write: %v", err)
	}
}

// TestIntervalIsADuration.
//
// `interval = "5m"` is what somebody expects to type. The alternative,
// interval_seconds, is the field that gets set to 300000 by accident.
func TestIntervalIsADuration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.WriteFile(path,
		[]byte("server = \"https://id.example\"\ninterval = \"90s\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := agent.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(cfg.Interval) != 90*time.Second {
		t.Fatalf("got %s, want 90s", time.Duration(cfg.Interval))
	}

	if err := os.WriteFile(path,
		[]byte("server = \"https://id.example\"\ninterval = \"soon\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.LoadConfig(path); err == nil {
		t.Fatal(`interval = "soon" was accepted`)
	}
}

// TestDiagnoseSkipsWhatIsSwitchedOff.
//
// A host running the agent only for identity has no sudoers path, and a report
// telling it about a sudoers include it will never use is noise. A report people
// skim is a report that stops catching things.
func TestDiagnoseSkipsWhatIsSwitchedOff(t *testing.T) {
	cfg := &agent.Config{
		Server:  "https://id.example",
		KeyPath: filepath.Join(t.TempDir(), "absent"),
		// Everything else empty: identity off, sudoers off, certificates off.
	}

	checks := agent.Diagnose(t.Context(), cfg)

	for _, c := range checks {
		switch c.Name {
		case "nsswitch", "userdb socket", "sudoers include", "sshd drop-in":
			t.Fatalf("%q was checked despite being switched off", c.Name)
		}
	}
	if len(checks) == 0 {
		t.Fatal("nothing at all was checked; enrollment always applies")
	}
}

// TestNotEnrolledIsFatal.
//
// The distinction the exit code rests on: a host with no key cannot do anything,
// and a host with no sshd simply has less to do. Only the first should stop a
// rollout.
func TestNotEnrolledIsFatal(t *testing.T) {
	cfg := &agent.Config{
		Server:  "https://id.example",
		KeyPath: filepath.Join(t.TempDir(), "absent"),
	}

	checks := agent.Diagnose(t.Context(), cfg)
	if agent.Ready(checks) {
		t.Fatal("a host with no key was reported ready")
	}

	// And with a key, the same configuration is ready — otherwise the assertion
	// above would hold for any reason at all.
	key := filepath.Join(t.TempDir(), "host_key")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.KeyPath = key

	if !agent.Ready(agent.Diagnose(t.Context(), cfg)) {
		t.Fatal("an enrolled host with nothing else configured was not ready")
	}
}
