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

// Up lists the forward migrations, in the order they apply.
//
// Explicitly not every *.sql file. A reversal lives beside the migration it
// undoes as `<name>.down.sql`, which the embed pattern also matches — so a naive
// glob would try to apply every drop immediately after the create that made it,
// and the first `cardinal migrate` against an empty database would leave no
// schema at all.
func Up() ([]string, error) {
	all, err := fs.Glob(FS, "*.sql")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(all))
	for _, name := range all {
		if strings.HasSuffix(name, downSuffix) {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// Down returns the reversal of a forward migration, if one exists.
//
// Absent is a legitimate answer rather than an error. Some changes cannot be
// undone in a way worth offering — dropping a column reverses to a column with
// no data in it, which is a different database wearing the same schema — and for
// those the honest reversal is a restore.
func Down(name string) ([]byte, bool) {
	body, err := FS.ReadFile(strings.TrimSuffix(name, ".sql") + downSuffix)
	if err != nil {
		return nil, false
	}
	return body, true
}

const downSuffix = ".down.sql"
