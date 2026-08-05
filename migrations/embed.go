// Package migrations embeds Cardinal's schema so a binary can apply it.
//
// Without this, deploying meant shipping the .sql files alongside the container
// and running psql against the database by hand — which works exactly until
// someone forgets, and then the symptom is a running server whose every request
// fails with "relation does not exist".
package migrations

import "embed"

// FS holds the schema migrations, applied in filename order.
//
// Filenames are zero-padded and never renumbered: the applied set is recorded
// by name, so renaming a migration would make an already-migrated database look
// like it needs it again.
//
//go:embed *.sql
var FS embed.FS
