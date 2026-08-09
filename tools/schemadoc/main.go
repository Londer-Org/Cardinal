// Command schemadoc writes docs/schema.md from a live database.
//
// Generated rather than hand-written, because a hand-written schema document is
// wrong within a month and then actively misleading — someone reads it, believes
// it, and designs against a column that moved. The database is the only thing
// that knows the truth, so it is the thing asked.
//
// One diagram per domain rather than one of everything. A Mermaid diagram of
// twenty-odd tables is a hairball nobody can read, which is the same failure as
// having no diagram at all but more work to produce.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// domains group tables into readable diagrams. A table not listed here lands in
// "Other", loudly, so that adding one to the schema and forgetting this file
// shows up in the document rather than silently disappearing from it.
var domains = []struct {
	Title  string
	Note   string
	Tables []string
}{
	{
		Title: "Directory",
		Note: "Identity is an immutable UUID and everything else is an attribute " +
			"([ADR 0002](adr/0002-identity-is-an-immutable-uuid.md)). Membership " +
			"carries a validity period rather than a boolean, so a grant can " +
			"expire without anything having to run.",
		Tables: []string{"entities", "group_members", "attribute_definitions"},
	},
	{
		Title: "Authentication",
		Note: "No password column exists. What a person can present is a passkey, " +
			"a recovery code, or — for a script — an access token, and each is " +
			"stored as a hash.",
		Tables: []string{
			"webauthn_credentials", "webauthn_ceremonies", "sessions",
			"access_tokens", "recovery_codes", "enrollment_invitations",
			"rate_limits",
		},
	},
	{
		Title: "Recovery",
		Note: "Restoring an account that can already sign in needs two " +
			"administrators, neither of them the subject " +
			"([ADR 0015](adr/0015-dual-control-recovery.md)).",
		Tables: []string{"recovery_requests", "recovery_approvals"},
	},
	{
		Title: "OpenID Connect",
		Note: "An application is a directory entity with client configuration " +
			"attached, so it can be a group member and a policy subject like " +
			"anything else.",
		Tables: []string{
			"oidc_clients", "oidc_client_keys", "oidc_auth_requests",
			"oidc_tokens", "oidc_consents", "oidc_signing_keys",
		},
	},
	{
		Title: "Policy and audit",
		Note: "`events` is a hash-chained journal with **no foreign key to " +
			"entities**, deliberately: erasure must not be able to break the " +
			"chain. `decisions` does reference the principal, which is why a " +
			"user with decisions against them is redacted rather than deleted.",
		Tables: []string{"policy_versions", "decisions", "events"},
	},
	{
		Title:  "Schema",
		Note:   "Applied migrations. Written by `cardinal migrate`.",
		Tables: []string{"schema_migrations"},
	},
}

type column struct {
	Name     string
	Type     string
	Nullable bool
	Default  string
	Comment  string
}

type foreignKey struct {
	Column    string
	RefTable  string
	RefColumn string
}

type table struct {
	Name        string
	Comment     string
	Columns     []column
	PrimaryKey  []string
	ForeignKeys []foreignKey
	Partitions  []string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "schemadoc: %v\n", err)
		os.Exit(1)
	}
}

// docPath is where the generated document lives, relative to the repository
// root. The tool is run from there, by `make schema`.
const docPath = "docs/schema.md"

func run() error {
	// check renders and compares instead of writing.
	//
	// It exists because the document was three migrations stale before anybody
	// noticed — missing the Shared Signals tables, SCIM's external_id and token
	// scopes — and the thing that noticed was a person regenerating it for an
	// unrelated reason. The header of the document warns that a schema document
	// maintained separately from the schema is worse than absent because
	// someone believes it. Nothing enforced that, so it happened.
	check := flag.Bool("check", false,
		"exit non-zero if "+docPath+" differs from the database, instead of rewriting it")
	flag.Parse()

	dsn := os.Getenv("CARDINAL_DSN")
	if dsn == "" {
		// The development database, whose password is "cardinal" and is in the
		// Makefile, the README and compose.yml already.
		dsn = "postgres://cardinal:cardinal@localhost:5433/cardinal?sslmode=disable" //nolint:gosec // local development default
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer pool.Close()

	tables, err := readTables(ctx, pool)
	if err != nil {
		return err
	}

	// Rendered into memory first, so writing and checking share one renderer.
	// Two paths that each produce "the document" would eventually disagree,
	// and that disagreement would be a check passing against a file nobody
	// could regenerate.
	var rendered bytes.Buffer
	out := &doc{w: &rendered}
	write(out, tables)
	if out.err != nil {
		return fmt.Errorf("rendering %s: %w", docPath, out.err)
	}

	if *check {
		return compare(rendered.Bytes())
	}

	// Written whole rather than streamed: a failure part-way through is the
	// difference between a document and half of one.
	if err := os.WriteFile(docPath, rendered.Bytes(), 0o644); err != nil { //nolint:gosec // a generated document that is committed and read by everybody
		return fmt.Errorf("writing %s: %w", docPath, err)
	}
	return nil
}

// compare reports whether the committed document still matches the database.
//
// It names the first line that differs rather than printing a diff. The
// document is thousands of lines of generated Mermaid and tables, a full diff
// in CI output is something people scroll past, and the action it supports is
// the same either way.
func compare(want []byte) error {
	have, err := os.ReadFile(docPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", docPath, err)
	}
	if bytes.Equal(have, want) {
		return nil
	}

	haveLines := strings.Split(string(have), "\n")
	wantLines := strings.Split(string(want), "\n")

	line, detail := 0, "one document is longer than the other"
	for i := range max(len(haveLines), len(wantLines)) {
		var h, w string
		if i < len(haveLines) {
			h = haveLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if h != w {
			line = i + 1
			detail = fmt.Sprintf("committed: %s\n  database:  %s", clip(h), clip(w))
			break
		}
	}

	return fmt.Errorf(
		"%s is out of date, from line %d:\n  %s\n\n"+
			"  Run `make schema` against a database with every migration applied.\n"+
			"  The document is generated — editing it by hand is how it gets here",
		docPath, line, detail)
}

// clip keeps a reported line short enough to read in CI output.
func clip(s string) string {
	const limit = 100
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}

// readTables asks the database what it actually contains.
//
// Partitions are folded into their parent rather than listed: `events_2026` is
// not a thing to design against, it is how `events` is stored.
func readTables(ctx context.Context, pool *pgxpool.Pool) (map[string]*table, error) {
	tables := map[string]*table{}

	rows, err := pool.Query(ctx, `
		SELECT c.relname,
		       coalesce(obj_description(c.oid), ''),
		       coalesce(parent.relname, '')
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  LEFT JOIN pg_inherits i ON i.inhrelid = c.oid
		  LEFT JOIN pg_class parent ON parent.oid = i.inhparent
		 WHERE n.nspname = 'public' AND c.relkind IN ('r','p')
		 ORDER BY c.relname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type parented struct{ name, parent string }
	var all []parented
	for rows.Next() {
		var name, comment, parent string
		if err := rows.Scan(&name, &comment, &parent); err != nil {
			return nil, err
		}
		all = append(all, parented{name, parent})
		if parent == "" {
			tables[name] = &table{Name: name, Comment: comment}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, p := range all {
		if p.parent != "" {
			if t, ok := tables[p.parent]; ok {
				t.Partitions = append(t.Partitions, p.name)
			}
		}
	}

	for name, t := range tables {
		if err := readColumns(ctx, pool, name, t); err != nil {
			return nil, err
		}
		if err := readKeys(ctx, pool, name, t); err != nil {
			return nil, err
		}
	}
	return tables, nil
}

func readColumns(ctx context.Context, pool *pgxpool.Pool, name string, t *table) error {
	rows, err := pool.Query(ctx, `
		SELECT a.attname,
		       format_type(a.atttypid, a.atttypmod),
		       NOT a.attnotnull,
		       coalesce(pg_get_expr(d.adbin, d.adrelid), ''),
		       coalesce(col_description(a.attrelid, a.attnum), '')
		  FROM pg_attribute a
		  LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		 WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
		 ORDER BY a.attnum`, "public."+name)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var c column
		if err := rows.Scan(&c.Name, &c.Type, &c.Nullable, &c.Default, &c.Comment); err != nil {
			return err
		}
		t.Columns = append(t.Columns, c)
	}
	return rows.Err()
}

func readKeys(ctx context.Context, pool *pgxpool.Pool, name string, t *table) error {
	pk, err := pool.Query(ctx, `
		SELECT a.attname
		  FROM pg_constraint con
		  JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ANY(con.conkey)
		 WHERE con.conrelid = $1::regclass AND con.contype = 'p'`, "public."+name)
	if err != nil {
		return err
	}
	for pk.Next() {
		var col string
		if scanErr := pk.Scan(&col); scanErr != nil {
			pk.Close()
			return scanErr
		}
		t.PrimaryKey = append(t.PrimaryKey, col)
	}
	pk.Close()

	fk, err := pool.Query(ctx, `
		SELECT a.attname, cl.relname, af.attname
		  FROM pg_constraint con
		  JOIN pg_attribute a  ON a.attrelid = con.conrelid  AND a.attnum  = con.conkey[1]
		  JOIN pg_class cl     ON cl.oid = con.confrelid
		  JOIN pg_attribute af ON af.attrelid = con.confrelid AND af.attnum = con.confkey[1]
		 WHERE con.conrelid = $1::regclass AND con.contype = 'f'
		 ORDER BY a.attname`, "public."+name)
	if err != nil {
		return err
	}
	defer fk.Close()

	for fk.Next() {
		var f foreignKey
		if err := fk.Scan(&f.Column, &f.RefTable, &f.RefColumn); err != nil {
			return err
		}
		t.ForeignKeys = append(t.ForeignKeys, f)
	}
	return fk.Err()
}

// doc collects the generated document and remembers the first write error.
//
// The generator makes roughly twenty writes in a row, and none of them can be
// recovered from individually: whatever fails the first — a full disk, a closed
// file — fails every one after it. Recording the first and checking once at the
// end says exactly that, where twenty ignored return values say nothing.
type doc struct {
	w   io.Writer
	err error
}

func (d *doc) printf(format string, a ...any) {
	if d.err != nil {
		return
	}
	_, d.err = fmt.Fprintf(d.w, format, a...)
}

func (d *doc) println(a ...any) {
	if d.err != nil {
		return
	}
	_, d.err = fmt.Fprintln(d.w, a...)
}

func (d *doc) print(a ...any) {
	if d.err != nil {
		return
	}
	_, d.err = fmt.Fprint(d.w, a...)
}

func write(out *doc, tables map[string]*table) {
	// Backticks are the whole point of a markdown document and would end a Go
	// raw string, so they are written as ~ and swapped back on the way out.
	// Errors surface when the file is closed, which run() checks.
	out.print(strings.ReplaceAll(`# Database schema

<!-- Generated by ~make schema~. Do not edit by hand: a schema document
     maintained separately from the schema is wrong within a month, and then
     worse than absent, because someone believes it. -->

Cardinal stores everything in one PostgreSQL database and nothing anywhere else
([ADR 0004](adr/0004-postgresql-is-the-only-datastore.md)) — no cache, no
session store, no second datastore to back up or reason about.

Three patterns recur, and reading them once makes the rest obvious:

- **Identity is a UUID.** Names are mutable attributes. Nothing references
  anything by name.
- **Validity is a range, not a flag.** ~tstzrange~ columns mean a grant, a
  session or a token expires because the range closed, not because a job ran.
  ~WITHOUT OVERLAPS~ makes contradictory grants impossible at the constraint
  level.
- **Credentials are stored as hashes.** A read of this database yields nothing
  that can be presented back to it.

Diagrams are per domain on purpose: one picture of every table is a hairball
nobody reads, which is the same outcome as having no picture.

`, "~", "\x60"))

	claimed := map[string]bool{}
	for _, d := range domains {
		for _, name := range d.Tables {
			claimed[name] = true
		}
	}
	var orphans []string
	for name := range tables {
		if !claimed[name] {
			orphans = append(orphans, name)
		}
	}
	sort.Strings(orphans)

	all := append([]struct {
		Title  string
		Note   string
		Tables []string
	}{}, domains...)
	if len(orphans) > 0 {
		all = append(all, struct {
			Title  string
			Note   string
			Tables []string
		}{
			Title: "Other",
			Note: "**Not yet grouped.** These tables exist in the database but are " +
				"not assigned to a domain in `tools/schemadoc/main.go`. Assign them " +
				"there so this document stays a map rather than a list.",
			Tables: orphans,
		})
	}

	for _, d := range all {
		out.printf("## %s\n\n%s\n\n", d.Title, d.Note)
		writeDiagram(out, tables, d.Tables)
		for _, name := range d.Tables {
			if t, ok := tables[name]; ok {
				writeTable(out, t)
			}
		}
	}
}

// writeDiagram draws one domain. Tables referenced from outside it appear as
// nodes without their columns, because the relationship matters and the
// borrowed table's shape belongs in its own section.
func writeDiagram(out *doc, tables map[string]*table, names []string) {
	inDomain := map[string]bool{}
	for _, n := range names {
		inDomain[n] = true
	}

	out.println("```mermaid")
	out.println("erDiagram")

	for _, name := range names {
		t, ok := tables[name]
		if !ok {
			continue
		}
		out.printf("    %s {\n", name)
		for _, c := range t.Columns {
			key := ""
			for _, pk := range t.PrimaryKey {
				if pk == c.Name {
					key = " PK"
				}
			}
			for _, fk := range t.ForeignKeys {
				if fk.Column == c.Name && key == "" {
					key = " FK"
				}
			}
			out.printf("        %s %s%s\n", mermaidType(c.Type), c.Name, key)
		}
		out.println("    }")
	}

	for _, name := range names {
		t, ok := tables[name]
		if !ok {
			continue
		}
		for _, fk := range t.ForeignKeys {
			out.printf("    %s ||--o{ %s : %s\n", fk.RefTable, name, fk.Column)
		}
	}
	out.println("```")
	out.println()
}

// mermaidType flattens Postgres types to something the diagram renderer accepts
// as an identifier. The real type is in the table below the diagram.
func mermaidType(t string) string {
	t = strings.NewReplacer(
		" ", "_", "(", "", ")", "", ",", "_", "[", "", "]", "_array",
	).Replace(t)
	if t == "" {
		return "unknown"
	}
	return t
}

func writeTable(out *doc, t *table) {
	out.printf("### `%s`\n\n", t.Name)
	if t.Comment != "" {
		out.printf("%s\n\n", t.Comment)
	}
	if len(t.Partitions) > 0 {
		sort.Strings(t.Partitions)
		out.printf("Partitioned by time: `%s`. Retention is a partition drop "+
			"rather than a delete.\n\n", strings.Join(t.Partitions, "`, `"))
	}

	out.println("| Column | Type | Null | Default | Notes |")
	out.println("|---|---|---|---|---|")
	for _, c := range t.Columns {
		null := "no"
		if c.Nullable {
			null = "yes"
		}
		def := c.Default
		if len(def) > 40 {
			def = def[:37] + "…"
		}
		if def != "" {
			def = "`" + def + "`"
		}
		notes := strings.ReplaceAll(c.Comment, "\n", " ")
		for _, fk := range t.ForeignKeys {
			if fk.Column == c.Name {
				ref := fmt.Sprintf("→ `%s.%s`", fk.RefTable, fk.RefColumn)
				if notes == "" {
					notes = ref
				} else {
					notes = ref + " — " + notes
				}
			}
		}
		out.printf("| `%s` | `%s` | %s | %s | %s |\n",
			c.Name, c.Type, null, def, notes)
	}
	out.println()
}
