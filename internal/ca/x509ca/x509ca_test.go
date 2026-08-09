package x509ca_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/ca/x509ca"
)

// Issuance needs a database and is covered end to end. What is checkable here
// is the constructor, and the one thing it guards is worth guarding: the
// authority's private key is sealed at rest, so a CA built without the key to
// open it is one that can only fail later, at the first certificate somebody
// urgently needs.

func TestNewRefusesAnAuthorityItCannotOpen(t *testing.T) {
	t.Parallel()

	_, err := x509ca.New(nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not stored in the clear",
		"the message should say why a key is needed, not merely that one is")
}

// TestSealKeyIsTheOneItWasGiven.
//
// ADR 0021 requires this key to be distinct from the OIDC signing key's and the
// SSH authority's, so that one leaked configuration file does not yield more
// than one authority. Nothing in code can enforce that three operator-chosen
// strings differ, but the CA must at least use the one it was handed rather
// than deriving or sharing one.
func TestSealKeyIsTheOneItWasGiven(t *testing.T) {
	t.Parallel()

	ca, err := x509ca.New(nil, "the-x509-key")
	require.NoError(t, err)
	assert.Equal(t, "the-x509-key", ca.SealKey())
}
