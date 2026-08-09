package arch

import (
	"go/ast"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The reachability guard next door asks whether exported Go methods have
// callers. These ask the same question at the three other layers where the
// answer has been "no" at least once: an HTTP handler nothing routes, a console
// view nothing links to, and a policy rule naming a group nothing creates.
//
// All three pass today. They are here because each one has been false before,
// and because the cost of a check that passes is a second of CI while the cost
// of the alternative is another audit.

// TestEveryHandlerIsRouted fails when an HTTP handler is never registered.
//
// A handler that is written, reviewed and never attached to the mux is the
// reachability bug at the transport layer: the code exists, the tests can call
// it directly and pass, and no request can ever reach it. The symptom is a 404
// on a feature everybody believes shipped.
func TestEveryHandlerIsRouted(t *testing.T) {
	root := repoRoot(t)
	api := filepath.Join(root, "internal", "server", "httpapi")

	declared := map[string]string{} // handler name -> file it is declared in
	referenced := map[string]bool{}

	walkGo(t, api, func(path string, file *ast.File, isTest bool) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !strings.HasPrefix(fn.Name.Name, "handle") {
				continue
			}
			if !isTest {
				declared[fn.Name.Name] = relative(root, path)
			}
		}

		// A reference is any selector naming it that is not the declaration —
		// mux.Handle("...", s.handleThing), a middleware wrapping it, or one
		// handler delegating to another.
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && strings.HasPrefix(sel.Sel.Name, "handle") && !isTest {
				referenced[sel.Sel.Name] = true
			}
			return true
		})
	})

	if len(declared) < 50 {
		t.Fatalf("only found %d handlers, so this test is looking in the wrong place", len(declared))
	}

	var orphaned []string
	for name, file := range declared {
		if !referenced[name] {
			orphaned = append(orphaned, name+"  ("+file+")")
		}
	}

	sort.Strings(orphaned)
	if len(orphaned) > 0 {
		t.Errorf("%d handler(s) are declared and never routed, so nothing can "+
			"reach them:\n\n\t%s", len(orphaned), strings.Join(orphaned, "\n\t"))
	}
}

// TestEveryConsoleViewIsReachable fails when a view is never imported.
//
// The console equivalent: a screen that was built, styled and left with no
// route and no link to it. Nobody deletes one on purpose — a route gets
// renamed during a refactor and the view it pointed at stays behind, still
// compiling, still in the bundle.
func TestEveryConsoleViewIsReachable(t *testing.T) {
	root := repoRoot(t)
	viewDir := filepath.Join(root, "web", "src", "views")

	entries, err := os.ReadDir(viewDir)
	if err != nil {
		t.Skipf("no console sources here: %v", err)
	}

	// Everything under web/src that could import a view.
	var sources []string
	err = filepath.WalkDir(filepath.Join(root, "web", "src"),
		func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !d.IsDir() && (strings.HasSuffix(path, ".tsx") || strings.HasSuffix(path, ".ts")) {
				body, readErr := os.ReadFile(path)
				if readErr != nil {
					return readErr
				}
				sources = append(sources, string(body))
			}
			return nil
		})
	if err != nil {
		t.Fatalf("reading console sources: %v", err)
	}

	var orphaned []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".tsx") {
			continue
		}
		base := strings.TrimSuffix(name, ".tsx")

		// Quoted, so `views/users` does not count as a reference to a view
		// called `user`.
		needle := "views/" + base
		found := false
		for _, src := range sources {
			if strings.Contains(src, needle+"'") || strings.Contains(src, needle+`"`) {
				found = true
				break
			}
		}
		if !found {
			orphaned = append(orphaned, name)
		}
	}

	sort.Strings(orphaned)
	if len(orphaned) > 0 {
		t.Errorf("%d console view(s) are never imported, so nothing routes to "+
			"them:\n\n\t%s", len(orphaned), strings.Join(orphaned, "\n\t"))
	}
}

// policyGroupRef matches a group named by the shipped policy set.
var policyGroupRef = regexp.MustCompile(`Cardinal::Group::"([0-9a-fA-F-]+)"`)

// lineComment strips a Cedar `//` comment.
//
// Crude on purpose: it would corrupt a `//` inside a string literal, and there
// is none in this file. The alternative is a Cedar parser to answer a question
// about which lines are live.
var lineComment = regexp.MustCompile(`//.*$`)

// TestShippedPolicyNamesNoGroupThatDoesNotExist is the one with a body count.
//
// Three rules in the 0.1.0 policy set named groups no migration ever created.
// A Cedar rule whose principal is a group that does not exist never matches,
// and because Cedar is default-deny, a rule that never matches is
// indistinguishable from a rule doing its job — the permission simply is not
// granted and nothing anywhere says why. They shipped, and they were found by
// reading the policy set against the migrations by hand.
//
// The engine can already answer this: Engine.Dangling resolves every reference
// against the directory. But it is wired to a *warning* — `cardinal policy
// test` prints to stderr and exits zero — and a warning in a command nobody
// runs on a schedule is not a control. This checks the shipped set against the
// shipped migrations, where both are known at build time and neither needs a
// database.
func TestShippedPolicyNamesNoGroupThatDoesNotExist(t *testing.T) {
	root := repoRoot(t)

	policy, err := os.ReadFile(filepath.Join(root, "policies", "cardinal.cedar"))
	if err != nil {
		t.Fatalf("reading the shipped policy set: %v", err)
	}

	migrations, err := os.ReadDir(filepath.Join(root, "migrations"))
	if err != nil {
		t.Fatalf("reading migrations: %v", err)
	}
	var schema strings.Builder
	for _, m := range migrations {
		if strings.HasSuffix(m.Name(), ".sql") {
			body, readErr := os.ReadFile(filepath.Join(root, "migrations", m.Name()))
			if readErr != nil {
				t.Fatalf("reading %s: %v", m.Name(), readErr)
			}
			schema.Write(body)
		}
	}
	created := schema.String()

	// Comments are stripped first. The shipped set documents how to narrow a
	// rule with an illustrative `Cardinal::Group::"<engineering-uuid>"`, which
	// is not a reference to anything and must not be read as one.
	var referenced []string
	for line := range strings.SplitSeq(string(policy), "\n") {
		live := lineComment.ReplaceAllString(line, "")
		for _, match := range policyGroupRef.FindAllStringSubmatch(live, -1) {
			referenced = append(referenced, match[1])
		}
	}

	if len(referenced) == 0 {
		t.Fatal("found no group references at all, so this test is asserting nothing")
	}

	seen := map[string]bool{}
	var dangling []string
	for _, id := range referenced {
		if seen[id] {
			continue
		}
		seen[id] = true
		if !strings.Contains(created, id) {
			dangling = append(dangling, id)
		}
	}

	sort.Strings(dangling)
	if len(dangling) > 0 {
		t.Errorf("the shipped policy set names %d group(s) that no migration "+
			"creates.\n\nA rule naming a group that does not exist never matches, "+
			"and default-deny makes that look exactly like the rule working:\n\n\t%s",
			len(dangling), strings.Join(dangling, "\n\t"))
	}
}
