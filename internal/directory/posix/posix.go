// Package posix holds the uid and gid numbers Cardinal hands out.
//
// Here rather than in the store because these are facts about Unix and about
// this deployment's policy, not about how anything is persisted — and the
// dependency that revealed it pointed the wrong way: `config` imported `store`
// for exactly these three symbols, which made configuration depend on
// persistence to answer a question neither of them is really about.
package posix

// Range bounds allocation.
type Range struct {
	Low, High int
}

const (
	// AllocationFloor is the lowest number Cardinal will hand out itself.
	//
	// Above the distribution's accounts and above systemd's DynamicUser
	// reservation, so a freshly allocated number never lands on either. Only a
	// floor: where allocation actually starts is configuration.
	AllocationFloor = 65536

	// SystemCeiling is the top of the distribution's own range. Below it are
	// root, daemon, and whatever the package manager created.
	SystemCeiling = 1000
)

// DefaultRange is where numbers come from when configuration is silent.
//
// Starts well above systemd's DynamicUser reservation (61184–65519) and far
// above the distribution's own accounts, and is large enough that nobody will
// reach the end of it. Deliberately not randomised per deployment the way
// FreeIPA does: that exists to make merging two directories safer, and Cardinal
// has no merge story to protect yet. Choosing a range per deployment is a
// setting rather than a surprise.
var DefaultRange = Range{Low: 100000, High: 999999}
