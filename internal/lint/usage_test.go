package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// What a binary's help says it does, against what it dispatches.
//
// The two drifted the moment `serve`, `migrate` and `init` moved to
// cardinal-server: `cardinal -h` kept offering all three, so somebody following
// the most-read documentation there is — the binary's own — was told to run a
// command that answers "unknown command".
//
// Both directions are checked, because they fail differently. A command the
// help does not mention is one nobody finds. A command the help mentions and
// the binary does not have is worse: it is an instruction that cannot work,
// from the one source a person has no reason to doubt.

// commandLine matches an entry in the usage text.
//
// Two spaces, a lowercase word, and — the part that matters — a column gap
// before its description. Without that last requirement this matched every
// wrapped line of prose that happened to begin with a lowercase word, which on
// the first run reported eight commands named "nobody", "running" and "signing".
var commandLine = regexp.MustCompile(`^  ([a-z][a-z0-9-]*)\b[^\n]*?\s{2,}\S`)

func TestUsageAndDispatchAgree(t *testing.T) {
	for _, binary := range []string{"cardinal", "cardinal-server"} {
		t.Run(binary, func(t *testing.T) {
			path := filepath.Join("..", "..", "cmd", binary, "main.go")
			dispatched, usage := readCommands(t, path)

			for name := range dispatched {
				if !usage[name] {
					t.Errorf("%s dispatches %q and its help never mentions it, so "+
						"nobody finds it", binary, name)
				}
			}
			for name := range usage {
				if !dispatched[name] {
					t.Errorf("%s offers %q in its help and does not dispatch it — an "+
						"instruction that cannot work, from the one source a person "+
						"has no reason to doubt", binary, name)
				}
			}
		})
	}
}

// readCommands returns what main.go dispatches and what its usage advertises.
func readCommands(t *testing.T, path string) (dispatched, usage map[string]bool) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	dispatched = map[string]bool{}
	usage = map[string]bool{}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CaseClause:
			// The dispatch switch. Case values are string literals, and the
			// help aliases are not commands.
			for _, expr := range node.List {
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				name := strings.Trim(lit.Value, `"`)
				switch name {
				case "help", "-h", "--help", "version":
					continue
				}
				if name != "" && !strings.HasPrefix(name, "-") {
					dispatched[name] = true
				}
			}

		case *ast.BasicLit:
			// The usage text is the one raw string literal long enough to be
			// it, which is sturdier than matching on a variable name.
			if node.Kind != token.STRING || !strings.HasPrefix(node.Value, "`") {
				return true
			}
			text := strings.Trim(node.Value, "`")
			if len(text) < 200 {
				return true
			}
			for line := range strings.SplitSeq(text, "\n") {
				m := commandLine.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				switch m[1] {
				case "cardinal", "cardinal-server", "help", "version":
					continue
				}
				usage[m[1]] = true
			}
		}
		return true
	})

	if len(dispatched) == 0 || len(usage) == 0 {
		t.Fatalf("read %d dispatched and %d advertised command(s) from %s, so this "+
			"is checking nothing", len(dispatched), len(usage), path)
	}
	return dispatched, usage
}
