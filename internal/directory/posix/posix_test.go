package posix_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.londer.be/cardinal/internal/directory/posix"
)

// The numbers in this package are load-bearing in a way constants usually are
// not: a uid Cardinal hands out lands on files, and a collision with an account
// the distribution created is not a conflict anybody notices until the wrong
// process owns something. The comments beside them make specific claims about
// what they clear, so these tests hold them to those claims.

// systemdDynamicUserHigh is the top of systemd's DynamicUser reservation.
//
// From systemd's own documentation and its SYSTEMD_UID_MIN/MAX defaults: the
// transient range is 61184–65519. A number allocated inside it can be handed to
// a service by systemd at any time, so nothing persistent may live there.
const systemdDynamicUserHigh = 65519

func TestAllocationClearsSystemdsTransientRange(t *testing.T) {
	t.Parallel()

	assert.Greater(t, posix.AllocationFloor, systemdDynamicUserHigh,
		"a number inside systemd's DynamicUser range can be reassigned to a "+
			"transient service, which would put two identities on one uid")
	assert.Greater(t, posix.DefaultRange.Low, systemdDynamicUserHigh)
}

func TestAllocationClearsTheDistributionsOwnAccounts(t *testing.T) {
	t.Parallel()

	assert.Greater(t, posix.AllocationFloor, posix.SystemCeiling,
		"below SystemCeiling are root, daemon and whatever the package manager created")
	assert.Greater(t, posix.DefaultRange.Low, posix.AllocationFloor,
		"the default range must start above the floor, not at or below it")
}

func TestDefaultRangeIsOrderedAndLarge(t *testing.T) {
	t.Parallel()

	assert.Less(t, posix.DefaultRange.Low, posix.DefaultRange.High,
		"an inverted range would allocate nothing, and the failure would arrive "+
			"at the first user rather than at startup")
	assert.Greater(t, posix.DefaultRange.High-posix.DefaultRange.Low, 100_000,
		"the comment claims nobody will reach the end of it")
}

// TestNothingCanBeAllocatedAsRoot is the one that would matter.
func TestNothingCanBeAllocatedAsRoot(t *testing.T) {
	t.Parallel()

	assert.NotZero(t, posix.DefaultRange.Low)
	assert.Positive(t, posix.AllocationFloor)
	assert.Greater(t, posix.SystemCeiling, 0,
		"a SystemCeiling of zero would make the floor check vacuous")
}
