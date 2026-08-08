package migrations_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/migrations"
)

// Migrations only add.
//
// This one rule replaces a great deal of machinery. If a migration never removes
// or narrows anything, the previous version of Cardinal keeps working against a
// schema newer than itself — so rolling back is deploying the old image and
// nothing else. No reversal to write, no ordering to remember, no backup to take
// first, and no way to be holding the wrong one of two procedures at the moment
// something is already going wrong.
//
// Removal still happens; it happens a release later, on purpose, once nothing
// running reads the thing being removed. A migration that cannot wait says so in
// its header and older versions refuse to start against it.
//
// Enforced here rather than written down because the failure is silent and
// arrives late: a `DROP COLUMN` merged on a Tuesday is only discovered by the
// rollback in November that no longer works.

// breakingHeader marks a migration that is deliberately not backwards
// compatible. `-- breaking: <why>` on a line of its own.
var breakingHeader = regexp.MustCompile(`(?im)^--\s*breaking:\s*(\S.*)$`)

// grandfathered are the migrations that predate this rule.
//
// They cannot be brought into line, and that is not laziness: a migration's
// digest is recorded when it is applied and checked on every subsequent run, so
// editing one makes every existing database refuse to migrate. The rule applies
// from here forward, and the list does not grow.
var grandfathered = map[string]string{
	"0010_drop_break_glass.sql":     "removed break-glass wholesale (ADR 0014)",
	"0022_posix_adoption_range.sql": "widened a CHECK by replacing it",
	"0013_group_kinds.sql":          "added a CHECK constraint alongside new columns",
	"0002_redaction.sql":            "added a CHECK constraint alongside a new column",
	"0014_sliding_sessions.sql":     "backfilled then set NOT NULL, in one migration",
	"0021_posix_adoption":           "placeholder; see the .sql entry",
	"0021_posix_adoption.sql":       "added a column later given meaning by 0022",
	"0001_foundation.sql":           "created everything; there was nothing to preserve",
}

// forbidden is what an expand-only migration may not do.
//
// Each pattern is something that removes or narrows, which is the same thing to
// a binary that is still reading the old shape.
var forbidden = []struct {
	name    string
	pattern *regexp.Regexp
	why     string
}{
	{
		"DROP TABLE", regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`),
		"a version still reading that table stops working",
	},
	{
		"DROP COLUMN", regexp.MustCompile(`(?i)\bDROP\s+COLUMN\b`),
		"a version still selecting that column stops working",
	},
	{
		"RENAME", regexp.MustCompile(`(?i)\bRENAME\b`),
		"a rename is a drop and an add, and the old name is what is being read",
	},
	{
		"ALTER COLUMN ... TYPE", regexp.MustCompile(`(?i)\bALTER\s+COLUMN\s+\w+\s+(SET\s+DATA\s+)?TYPE\b`),
		"a changed type is a changed contract, whatever the values look like",
	},
	{
		"SET NOT NULL", regexp.MustCompile(`(?i)\bSET\s+NOT\s+NULL\b`),
		"a version that does not write the column starts failing to insert",
	},
	{
		"DROP CONSTRAINT", regexp.MustCompile(`(?i)\bDROP\s+CONSTRAINT\b`),
		"dropping a constraint is additive, but replacing it with a narrower one is not — mark it breaking if that is what this is",
	},
	{
		"DROP DEFAULT", regexp.MustCompile(`(?i)\bDROP\s+DEFAULT\b`),
		"a version relying on the default starts inserting nulls or failing",
	},
}

// addColumn finds new columns so their nullability can be checked.
var addColumn = regexp.MustCompile(`(?is)ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s+([^,;]+)`)

func TestMigrationsOnlyAdd(t *testing.T) {
	up, err := migrations.Up()
	require.NoError(t, err)
	require.NotEmpty(t, up)

	for _, name := range up {
		t.Run(name, func(t *testing.T) {
			body, err := migrations.FS.ReadFile(name)
			require.NoError(t, err)
			sql := stripComments(string(body))

			if why, old := grandfathered[name]; old {
				t.Skipf("predates this rule: %s", why)
			}
			if m := breakingHeader.FindSubmatch(body); m != nil {
				t.Logf("declared breaking: %s", strings.TrimSpace(string(m[1])))
				return
			}

			for _, rule := range forbidden {
				assert.False(t, rule.pattern.MatchString(sql),
					"%s is not expand-only: %s.\n\nEither split it — add now, remove a "+
						"release later once nothing reads it — or, if it genuinely cannot "+
						"wait, put `-- breaking: <why>` at the top. Older versions then "+
						"refuse to start against this schema instead of failing one "+
						"request at a time.", rule.name, rule.why)
			}

			// A new NOT NULL column with no default breaks every INSERT the
			// previous version makes, which is the same outage as a drop and
			// much easier to write by accident.
			for _, m := range addColumn.FindAllStringSubmatch(sql, -1) {
				definition := m[2]
				notNull := regexp.MustCompile(`(?i)\bNOT\s+NULL\b`).MatchString(definition)
				hasDefault := regexp.MustCompile(`(?i)\bDEFAULT\b|\bGENERATED\b`).MatchString(definition)
				assert.False(t, notNull && !hasDefault,
					"column %q is NOT NULL with no DEFAULT, so an insert by the previous "+
						"version fails. Give it a default, or make it nullable and tighten "+
						"it a release later", m[1])
			}
		})
	}
}

// stripComments removes -- and /* */ so a rule named in prose is not mistaken
// for one being performed. Several of these files discuss dropping things.
func stripComments(sql string) string {
	sql = regexp.MustCompile(`(?m)--.*$`).ReplaceAllString(sql, "")
	return regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(sql, "")
}
