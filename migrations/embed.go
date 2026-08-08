// Package migrations embeds Cardinal's schema so a binary can apply it.
//
// Without this, deploying meant shipping the .sql files alongside the container
// and running psql against the database by hand — which works exactly until
// someone forgets, and then the symptom is a running server whose every request
// fails with "relation does not exist".
package migrations

import (
	"embed"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

// FS holds the schema migrations, applied in filename order.
//
// Filenames are zero-padded and never renumbered: the applied set is recorded
// by name, so renaming a migration would make an already-migrated database look
// like it needs it again.
//
//go:embed *.sql
var FS embed.FS

// Up lists the migrations, in the order they apply.
func Up() ([]string, error) {
	out, err := fs.Glob(FS, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// breakingHeader marks a migration that is deliberately not backwards
// compatible: `-- breaking: <why>` on a line of its own.
var breakingHeader = regexp.MustCompile(`(?im)^--\s*breaking:\s*(\S.*)$`)

// Breaking reports whether a migration declares itself incompatible with the
// previous version, and why.
//
// Migrations are expand-only — enforced by a test — so the answer is almost
// always no, and that is what makes rolling back a matter of deploying the old
// image. The exception exists because "never" would be a lie somebody eventually
// has to work around quietly, and a declared exception is one an older binary
// can refuse to run against.
//
// The reason travels into the database when the migration is applied, which is
// the whole point: a version from before this migration existed cannot read the
// file, but it can read the row.
func Breaking(name string) (string, bool) {
	body, err := FS.ReadFile(name)
	if err != nil {
		return "", false
	}
	m := breakingHeader.FindSubmatch(body)
	if m == nil {
		return "", false
	}
	return strings.TrimSpace(string(m[1])), true
}
