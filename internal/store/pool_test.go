package store_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/store"
)

// TestPoolLimitsReachThePool.
//
// The setting existed, was validated, appeared on the configuration page, and
// never reached pgx for two releases — so an operator tuning a busy deployment
// silently got max(4, NumCPU) connections while the console showed the number
// they had chosen. Asserted against the live pool rather than against the
// struct that was passed in, because the struct being right is exactly what was
// true the whole time it was broken.
func TestPoolLimitsReachThePool(t *testing.T) {
	s, err := store.OpenWithLimits(t.Context(), sharedDSN, store.PoolLimits{
		MaxConns:        7,
		ConnMaxLifetime: 11 * time.Minute,
	})
	require.NoError(t, err)
	t.Cleanup(s.Close)

	assert.Equal(t, int32(7), s.Pool().Config().MaxConns)
	assert.Equal(t, 11*time.Minute, s.Pool().Config().MaxConnLifetime)
}

// TestTheConnectionStringWins.
//
// pgx reads pool_max_conns from the DSN itself. Overriding one somebody wrote
// there would replace a setting that works with one that looks like it does,
// which is the same bug in the other direction.
func TestTheConnectionStringWins(t *testing.T) {
	s, err := store.OpenWithLimits(t.Context(), sharedDSN+"&pool_max_conns=3",
		store.PoolLimits{MaxConns: 7})
	require.NoError(t, err)
	t.Cleanup(s.Close)

	assert.Equal(t, int32(3), s.Pool().Config().MaxConns,
		"the configuration file overrode a pool size written into the DSN")
}

// TestZeroLeavesPgxAlone: `cardinal migrate` and the CLI have a DSN long before
// they have a configuration file, and a one-shot command has no opinion about
// pool sizing.
func TestZeroLeavesPgxAlone(t *testing.T) {
	s, err := store.Open(t.Context(), sharedDSN)
	require.NoError(t, err)
	t.Cleanup(s.Close)

	assert.Positive(t, s.Pool().Config().MaxConns,
		"opening without limits must leave a usable pool, not a zero-sized one")
}
