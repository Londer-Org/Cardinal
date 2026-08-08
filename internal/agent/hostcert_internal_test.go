// Package-internal tests.
//
// validateSSHDConfig is unexported, and the behaviour worth pinning down is
// exactly how it reads sshd's exit — which is not visible from outside the
// package and should not be exported just to be tested.
package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAMachineWithNoHostKeysStillValidatesTheDropIn.
//
// sshd needs host keys, and `sshd -T` exits non-zero without them however good
// the configuration is. A container or a CI runner has none, so this check
// failed there for a reason that had nothing to do with the drop-in — and the
// agent reported it as "sshd rejected the drop-in", which sends whoever is
// debugging to the wrong file.
//
// Measured rather than assumed, on alpine with /etc/ssh/ssh_host_* removed:
//
//	valid config,   no host keys -> exit 1,   "no hostkeys available"
//	invalid config, no host keys -> exit 255, names the bad option
//
// The two are distinguishable, and reaching the first proves the config parsed,
// because sshd loads keys only after accepting it. A stub standing in for sshd
// reproduces both, so this runs anywhere — including the machines that have
// host keys and could never have shown the bug.
func TestAMachineWithNoHostKeysStillValidatesTheDropIn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		script  string
		wantErr bool
	}{
		{
			name: "no host keys, valid config",
			// What a runner does: parse the config, then fail on keys.
			script:  "#!/bin/sh\necho 'sshd: no hostkeys available -- exiting.' >&2\nexit 1\n",
			wantErr: false,
		},
		{
			name:    "a genuinely bad directive",
			script:  "#!/bin/sh\necho '/x.conf: line 1: Bad configuration option: Nope' >&2\nexit 255\n",
			wantErr: true,
		},
		{
			name:    "accepted outright",
			script:  "#!/bin/sh\nexit 0\n",
			wantErr: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stub := filepath.Join(dir, "sshd")
			if err := os.WriteFile(stub, []byte(tc.script), 0o755); err != nil { //nolint:gosec // a stub in a temp dir
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)

			config := filepath.Join(dir, "drop-in.conf")
			if err := os.WriteFile(config, []byte("HostCertificate /x\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			err := validateSSHDConfig(t.Context(), config)
			if tc.wantErr && err == nil {
				t.Fatal("a rejected drop-in was reported as accepted")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("a valid drop-in was reported as rejected: %v", err)
			}
		})
	}
}
