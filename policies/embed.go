// Package policies embeds the default policy set so a binary carries it.
//
// Without this, `cardinal init` read policies/cardinal.cedar from the working
// directory — which is fine from a source checkout and impossible in the
// released image, whose whole filesystem is one static binary. First-run in a
// container therefore failed at the first step, before an administrator was
// created, on a file the image was never going to contain.
//
// Embedding it also settles what "the default policy set" means for a
// deployment that cannot edit files: the binary carries the starting point, the
// database holds what is live, and `cardinal policy publish` or the console
// moves between them. Nothing about running from an image makes policy
// unchangeable — the file was never the thing being enforced.
package policies

import _ "embed"

// Default is the policy set a fresh deployment starts with.
//
// Published and activated by `cardinal init`, and thereafter only ever read
// from the database. An upgrade does not republish it: a deployment's policy is
// its own, and silently replacing it would undo whatever anybody had changed.
// The consequence — that a set from an older release keeps running against a
// newer binary — is what Engine.UngovernedActions exists to report.
//
//go:embed cardinal.cedar
var Default []byte
