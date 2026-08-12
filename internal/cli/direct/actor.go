package direct

import "github.com/google/uuid"

// Actor is what the direct path records as having acted.
//
// Migration 0035 creates the entity. What matters here is why it is not the
// obvious alternatives:
//
// Not nil, because group_members.granted_by is NOT NULL and every read renders
// an actor. A nullable column would push "unknown" into every audit view for a
// case that is not unknown — the path is known exactly, only the person is not.
//
// Not the member, which is what this replaced: `cardinal grant engineers alice`
// recorded alice as her own granter, and no query could tell that from a real
// self-grant. Attribution nobody can check is worse than none, because it reads
// as evidence.
//
// Not a login passed on the command line. Whoever holds the connection string
// can type any name, so `-as somebody` would record an assertion by an
// unauthenticated caller and render it beside attributions that were proven.
// The client CLI signs in; that is where a real name comes from.
var Actor = uuid.MustParse("00000000-0000-7000-8000-0000000000d1")

// ActorID is Actor as a pointer, for the store calls that take an optional one.
func ActorID() *uuid.UUID {
	id := Actor
	return &id
}
