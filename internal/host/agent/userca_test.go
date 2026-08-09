package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Two real ed25519 authority keys, so the parse check has something to parse.
const (
	caKeyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7t5cQD5xNTf1Cnz1qLqSjHrmqBBiP2Vs3+Mc1lQ5cX cardinal-ca-a"
	caKeyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILkOoEt7uCVJdBpCEr8Wr9OWQAOKQ2SUFVEcC0DLo1Xf cardinal-ca-b"
)

func agentWithCAPath(t *testing.T) *Agent {
	t.Helper()
	return &Agent{UserCAPath: filepath.Join(t.TempDir(), "cardinal_user_ca.pub")}
}

// TestTrustIsInstalledAndRotates.
//
// The gap this closes: TrustedUserCAKeys was a manual operator step, which made
// rotating the authority a manual fleet-wide operation — the kind nobody
// performs, so in practice the first key was the only key and the rotation
// machinery on the server had nothing to converge on.
func TestTrustIsInstalledAndRotates(t *testing.T) {
	a := agentWithCAPath(t)

	changed, err := a.writeUserCAKeys([]string{caKeyA})
	require.NoError(t, err)
	assert.True(t, changed)

	installed, err := a.TrustedUserCAKeys()
	require.NoError(t, err)
	assert.Equal(t, []string{caKeyA}, installed)

	// A rotation: the new key signs, the old stays trusted until its grace
	// period ends. Both arrive, because a host trusting only the signing key
	// would reject certificates issued minutes before the switch.
	changed, err = a.writeUserCAKeys([]string{caKeyA, caKeyB})
	require.NoError(t, err)
	assert.True(t, changed)

	installed, err = a.TrustedUserCAKeys()
	require.NoError(t, err)
	assert.Equal(t, []string{caKeyA, caKeyB}, installed)

	// And the retirement completing.
	_, err = a.writeUserCAKeys([]string{caKeyB})
	require.NoError(t, err)
	installed, err = a.TrustedUserCAKeys()
	require.NoError(t, err)
	assert.Equal(t, []string{caKeyB}, installed,
		"a key past its grace period is still trusted here")
}

// TestAnEmptyAnswerLeavesTrustAlone.
//
// The important one. An older server omits the field and a server with no
// authority sends none, and both decode identically — so an agent that deleted
// the file on an empty answer would remove trust an operator installed by hand
// during an agent-first upgrade. That is the agent changing how the machine
// authenticates people, which is the one thing it may not do.
func TestAnEmptyAnswerLeavesTrustAlone(t *testing.T) {
	a := agentWithCAPath(t)
	require.NoError(t, os.WriteFile(a.UserCAPath, []byte(caKeyA+"\n"), 0o644))

	changed, err := a.writeUserCAKeys(nil)
	require.NoError(t, err)
	assert.False(t, changed)

	installed, err := a.TrustedUserCAKeys()
	require.NoError(t, err)
	assert.Equal(t, []string{caKeyA}, installed,
		"an empty answer removed trust the agent did not install")
}

// TestAnUnparseableKeyIsRefusedBeforeItIsWritten.
//
// The only check there is. `sshd -t` accepts a TrustedUserCAKeys file
// containing `not a key at all` — measured — so the usual net of validating the
// config and refusing if the daemon does catches nothing here. Refusing keeps
// the previous file, which works.
func TestAnUnparseableKeyIsRefusedBeforeItIsWritten(t *testing.T) {
	a := agentWithCAPath(t)
	require.NoError(t, os.WriteFile(a.UserCAPath, []byte(caKeyA+"\n"), 0o644))

	_, err := a.writeUserCAKeys([]string{caKeyB, "not a key at all"})
	require.Error(t, err)

	installed, err := a.TrustedUserCAKeys()
	require.NoError(t, err)
	assert.Equal(t, []string{caKeyA}, installed,
		"a rejected update replaced the working file anyway")
}

// TestUnchangedTrustIsNotRewritten: this runs every refresh interval and the
// authority rotates about once a year, so the file's mtime is the answer to
// "when did trust last change here" — a question asked during an incident.
func TestUnchangedTrustIsNotRewritten(t *testing.T) {
	a := agentWithCAPath(t)

	_, err := a.writeUserCAKeys([]string{caKeyA})
	require.NoError(t, err)
	before, err := os.Stat(a.UserCAPath)
	require.NoError(t, err)

	changed, err := a.writeUserCAKeys([]string{caKeyA})
	require.NoError(t, err)
	assert.False(t, changed, "an unchanged list rewrote the file")

	after, err := os.Stat(a.UserCAPath)
	require.NoError(t, err)
	assert.Equal(t, before.ModTime(), after.ModTime())
}

// TestNoPathLeavesTheMachineAlone: an empty path is how a test, and an operator
// managing trust themselves, keeps the agent out of /etc/ssh entirely.
func TestNoPathLeavesTheMachineAlone(t *testing.T) {
	a := &Agent{}

	changed, err := a.writeUserCAKeys([]string{caKeyA})
	require.NoError(t, err)
	assert.False(t, changed)

	installed, err := a.TrustedUserCAKeys()
	require.NoError(t, err)
	assert.Empty(t, installed)
}
