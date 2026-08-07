package store_test

import (
	"testing"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrincipalsAreTheDirectoryNameAndNothingDerived.
//
// The temptation is to hand web-01.prod the short name `web-01` for free.
// Refused: web-01.dev would get it too, and whichever answered first when
// somebody typed `ssh web-01` would be trusted — an impersonation created by a
// convenience nobody asked for.
func TestPrincipalsAreTheDirectoryNameAndNothingDerived(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")

	principals, err := s.HostPrincipals(ctx, host.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"web-01.prod"}, principals)
}

// TestAliasesAreAdditional.
func TestAliasesAreAdditional(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")
	require.NoError(t, s.AddHostAlias(ctx, host.ID, "www.example.com", nil))
	require.NoError(t, s.AddHostAlias(ctx, host.ID, "web-01", nil))

	principals, err := s.HostPrincipals(ctx, host.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"web-01.prod", "www.example.com", "web-01"}, principals,
		"the directory name comes first, then aliases in the order granted")
}

// TestTwoHostsCannotHoldOneName.
//
// The constraint the table exists for. Two certificates for git.example.com
// means whichever machine answers first is trusted, which is not the sort of
// thing to discover during an incident.
func TestTwoHostsCannotHoldOneName(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	first := mustCreate(t, s, directory.TypeHost, "web-01.prod")
	second := mustCreate(t, s, directory.TypeHost, "web-02.prod")

	require.NoError(t, s.AddHostAlias(ctx, first.ID, "git.example.com", nil))

	err := s.AddHostAlias(ctx, second.ID, "git.example.com", nil)
	require.ErrorIs(t, err, store.ErrNameTaken)
}

// TestAnAliasCannotShadowAnotherHostsDirectoryName.
//
// The check no constraint can make, because aliases and entity names live in
// different tables. It is the worse half of the collision: the impersonated
// machine is real, and would keep working while another one answered for it.
func TestAnAliasCannotShadowAnotherHostsDirectoryName(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	attacker := mustCreate(t, s, directory.TypeHost, "web-01.prod")
	mustCreate(t, s, directory.TypeHost, "vault.prod")

	err := s.AddHostAlias(ctx, attacker.ID, "vault.prod", nil)
	require.ErrorIs(t, err, store.ErrNameTaken)
	assert.Contains(t, err.Error(), "directory name of another host")
}

// TestAHostMayAliasItsOwnName.
//
// Pointless and harmless, and refusing it would mean the collision check had to
// know the difference — which is the sort of special case that is wrong once and
// then wrong forever.
func TestAHostMayAliasItsOwnName(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")
	require.NoError(t, s.AddHostAlias(ctx, host.ID, "web-01.prod", nil))

	principals, err := s.HostPrincipals(ctx, host.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"web-01.prod", "web-01.prod"}, principals)
}

// TestRemovingAnAliasFreesTheName.
func TestRemovingAnAliasFreesTheName(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	first := mustCreate(t, s, directory.TypeHost, "web-01.prod")
	second := mustCreate(t, s, directory.TypeHost, "web-02.prod")

	require.NoError(t, s.AddHostAlias(ctx, first.ID, "git.example.com", nil))
	require.NoError(t, s.RemoveHostAlias(ctx, first.ID, "git.example.com", nil))
	require.NoError(t, s.AddHostAlias(ctx, second.ID, "git.example.com", nil))

	principals, err := s.HostPrincipals(ctx, first.ID)
	require.NoError(t, err)
	assert.NotContains(t, principals, "git.example.com")
}

// TestADisabledHostHasNoPrincipals.
//
// And the caller gets an error rather than an empty list, because OpenSSH reads
// a certificate with no principals as valid for *every* hostname — an empty
// slice reaching the signer would mint the worst possible certificate.
func TestADisabledHostHasNoPrincipals(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")
	require.NoError(t, s.AddHostAlias(ctx, host.ID, "www.example.com", nil))
	require.NoError(t, s.DisableEntity(ctx, host.ID, nil))

	_, err := s.HostPrincipals(ctx, host.ID)
	require.ErrorIs(t, err, directory.ErrNotFound)
}
