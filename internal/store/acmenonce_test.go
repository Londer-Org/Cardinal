package store_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/store"
)

// TestPurgingNoncesLeavesTheSpendableOnes.
//
// The purge and the consume share store.ACMENonceTTL, and this is why. A purge
// window shorter than the consume window deletes nonces a client is still
// entitled to spend, turning a working ACME exchange into "unknown or replayed
// nonce" — which reads as an attack rather than as a maintenance job, and would
// be diagnosed as one.
//
// This routine was written and called by nothing until 0.2.0, so nonces
// accumulated for the life of a deployment. Not a correctness problem, because
// every read enforces expiry, which is exactly why nobody noticed.
func TestPurgingNoncesLeavesTheSpendableOnes(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	fresh, err := s.NewACMENonce(ctx)
	require.NoError(t, err)

	stale, err := s.NewACMENonce(ctx)
	require.NoError(t, err)
	// Backdated past the window rather than waiting an hour. The row is the
	// only thing that decides, so moving it is the same experiment.
	_, err = s.Pool().Exec(ctx,
		`UPDATE acme_nonces SET issued_at = now() - interval '2 hours' WHERE nonce = $1`,
		stale)
	require.NoError(t, err)

	purged, err := s.PurgeACMENonces(ctx, store.ACMENonceTTL)
	require.NoError(t, err)
	assert.Equal(t, int64(1), purged, "the purge took something it should not have")

	require.NoError(t, s.ConsumeACMENonce(ctx, fresh),
		"a nonce inside the window was purged, so a live ACME exchange would "+
			"fail with what looks like a replay")

	assert.ErrorIs(t, s.ConsumeACMENonce(ctx, stale), store.ErrNonceUnknown)
}

// TestANonceIsSpentOnce: the delete is the check, so two requests replaying one
// nonce cannot both find it present.
func TestANonceIsSpentOnce(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	nonce, err := s.NewACMENonce(ctx)
	require.NoError(t, err)

	require.NoError(t, s.ConsumeACMENonce(ctx, nonce))
	assert.ErrorIs(t, s.ConsumeACMENonce(ctx, nonce), store.ErrNonceUnknown)
}
