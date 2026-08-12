package lint_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A client command must not be able to reach the database.
//
// The whole of ADR 0033 rests on one property: a command either goes through
// the API, where policy governs it and the journal names who ran it, or it is
// one of the few bootstrap commands that deliberately does not. One
// `store.Open` in a client command restores the situation the ADR exists to
// remove — no policy on the path, no truthful actor — and it would look like an
// ordinary import in an ordinary file.
//
// So it is a test rather than a convention. This is the same reasoning as the
// expand-only migration rule: the failure is silent, and it arrives long after
// the commit that caused it.

// forbidden maps a package prefix to the imports it may not have, and why.
var forbidden = []struct {
	dir     string
	imports []string
	why     string
}{
	{
		dir:     filepath.Join("internal", "cli", "command"),
		imports: []string{"go.londer.be/cardinal/internal/store"},
		why: "a client command reaches the API, so that policy governs it and the " +
			"journal names who ran it (ADR 0033). Reaching the database directly " +
			"is what bootstrap commands are for, and they live elsewhere",
	},
	{
		dir:     filepath.Join("internal", "cli", "api"),
		imports: []string{"go.londer.be/cardinal/internal/store"},
		why: "the API client speaks HTTP. An import of the store here would mean " +
			"some call is answered locally, which is the divergence this layout " +
			"exists to prevent",
	},
}

func TestClientCommandsCannotReachTheDatabase(t *testing.T) {
	root := filepath.Join("..", "..")

	for _, rule := range forbidden {
		dir := filepath.Join(root, rule.dir)
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("%s does not exist, so this test guards nothing", rule.dir)
		}

		var files int
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			files++

			parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}
			for _, spec := range parsed.Imports {
				imported := strings.Trim(spec.Path.Value, `"`)
				for _, banned := range rule.imports {
					if imported == banned || strings.HasPrefix(imported, banned+"/") {
						t.Errorf("%s imports %s\n      → %s",
							filepath.ToSlash(path), imported, rule.why)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// A rule that guards an empty directory passes and means nothing, which
		// is the failure this whole file exists to avoid elsewhere.
		if files == 0 {
			t.Errorf("%s contains no Go files, so this rule proves nothing", rule.dir)
		}
	}
}
