// Package arch holds tests about the shape of the codebase rather than its
// behaviour — the constraints that are true of the whole thing and that no
// single package's tests can see.
package arch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestNoExportedMethodIsUnreachable fails when an exported method has no caller
// outside the package that declares it.
//
// This exists because the same bug shape has now appeared six times: something
// implemented carefully, given a test, documented as though it were in use, and
// wired to nothing. Twice it was security-relevant. RevokeTokensForSession
// carried the comment "Called on sign-out" and had no caller, so signing out of
// Cardinal closed the session and left the access tokens minted from it live.
// Provider.RotateSigningKey had none either, so the key that signs every token
// could not be rotated at all.
//
// Both were found by hand, twice, months apart. A grep is not a control.
//
// The check is deliberately name-based rather than type-resolved: it asks
// whether the identifier is ever selected outside its own package. That
// under-reports — a method sharing a name with a reachable one elsewhere passes
// — and cannot over-report on a mere name collision. A gate that cries wolf is
// a gate someone switches off, so the bias is towards silence over noise, and
// the two real findings are both caught regardless.
func TestNoExportedMethodIsUnreachable(t *testing.T) {
	root := repoRoot(t)

	var (
		methods         []method
		exemptTypes     = map[string]bool{}
		interfaceMethod = map[string]bool{}
		// usedIn maps an identifier to every package directory that selects it.
		usedIn = map[string]map[string]bool{}
	)

	// The whole module, not the two directories the interesting types live in.
	//
	// Scanning only cmd/ and internal/ reported Agent.InstallUserCAKeys as
	// unreachable when tools/hostcheck calls it — the harness behind
	// `make verify-host` is a caller like any other, and a check that cannot
	// see a whole directory reports absence of evidence as evidence.
	{
		walkGo(t, root, func(path string, file *ast.File, isTest bool) {
			pkgDir := filepath.Dir(path)

			for _, decl := range file.Decls {
				collectAssertions(decl, exemptTypes)

				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || !fn.Name.IsExported() || isTest {
					continue
				}
				methods = append(methods, method{
					Name: fn.Name.Name, Recv: receiverName(fn), Dir: pkgDir,
					Pos: relative(root, path),
				})
			}

			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.InterfaceType:
					// A method satisfying an interface declared anywhere in the
					// module is reachable through it, and the call site names
					// the interface rather than the concrete type.
					for _, m := range node.Methods.List {
						for _, name := range m.Names {
							interfaceMethod[name.Name] = true
						}
					}
				case *ast.SelectorExpr:
					// Test files count as usage for the "which packages use
					// this" question only in the sense that they are excluded:
					// a method reachable exclusively from tests is exactly the
					// bug this looks for.
					if isTest {
						return true
					}
					if usedIn[node.Sel.Name] == nil {
						usedIn[node.Sel.Name] = map[string]bool{}
					}
					usedIn[node.Sel.Name][pkgDir] = true
				}
				return true
			})
		})
	}

	var unreachable []string
	for _, m := range methods {
		if exemptTypes[m.Recv] || interfaceMethod[m.Name] || satisfiesStdlib[m.Name] {
			continue
		}
		// An exported method on an unexported type cannot be called by naming
		// the type from outside, so the only thing it can be is an interface
		// implementation — which is what the whole of oidcprovider/adapters.go
		// is. Flagging those would bury the real findings under thirty-odd
		// entries nobody can act on.
		if !ast.IsExported(m.Recv) {
			continue
		}
		if reason, ok := allowed[m.Recv+"."+m.Name]; ok {
			if reason == "" {
				t.Errorf("%s.%s is allowed with no reason given", m.Recv, m.Name)
			}
			continue
		}

		// Called from any non-test file at all, including its own package.
		//
		// Requiring a caller in *another* package looked stricter and was
		// mostly noise: it flagged Agent.Refresh, Notifier.Emit and Store.InTx,
		// which are called perfectly normally from a few lines away and are
		// merely exported more widely than they need to be. That is a style
		// question. The bug this guards against is different in kind — code
		// with no caller anywhere — and burying nine of those in twenty
		// entries is how a gate stops being read.
		if len(usedIn[m.Name]) == 0 {
			unreachable = append(unreachable, m.Recv+"."+m.Name+"  ("+m.Pos+")")
		}
	}

	sort.Strings(unreachable)
	if len(unreachable) > 0 {
		t.Errorf(
			"%d exported method(s) are called from nowhere but their own tests.\n\n"+
				"Each is either dead code to delete, a duplicate of something that "+
				"is used, or a capability that was built and never wired up — which "+
				"is how signing out stopped revoking tokens and how an erased "+
				"account kept a working passkey. If one is genuinely reachable in "+
				"a way this cannot see, add it to `allowed` with the reason.\n\n\t%s",
			len(unreachable), strings.Join(unreachable, "\n\t"))
	}
}

type method struct{ Name, Recv, Dir, Pos string }

// allowed lists methods that are reachable in a way this test cannot see, each
// with the reason. A bare entry is itself a failure: an exemption whose
// justification nobody wrote is an exemption nobody can re-evaluate.
var allowed = map[string]string{}

// satisfiesStdlib are method names the standard library or a dependency calls
// on our types by interface. Named rather than resolved because resolving them
// would mean type-checking the whole module to learn what this list already
// says.
var satisfiesStdlib = map[string]bool{
	"Error": true, "String": true, "ServeHTTP": true, "Close": true,
	"Read": true, "Write": true, "Unwrap": true, "Is": true, "As": true,
	"MarshalJSON": true, "UnmarshalJSON": true, "MarshalText": true,
	"UnmarshalText": true, "Value": true, "Scan": true, "Deadline": true,
	"Done": true, "Err": true, "Handle": true, "Enabled": true,
	"WithAttrs": true, "WithGroup": true,
}

// collectAssertions records `var _ Interface = (*T)(nil)`, which declares that
// T's methods are called through Interface and so names no call site.
func collectAssertions(decl ast.Decl, into map[string]bool) {
	gen, ok := decl.(*ast.GenDecl)
	if !ok || gen.Tok != token.VAR {
		return
	}
	for _, spec := range gen.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || value.Names[0].Name != "_" {
			continue
		}
		for _, v := range value.Values {
			call, ok := v.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				continue
			}
			if paren, ok := call.Fun.(*ast.ParenExpr); ok {
				if star, ok := paren.X.(*ast.StarExpr); ok {
					if ident, ok := star.X.(*ast.Ident); ok {
						into[ident.Name] = true
					}
				}
			}
		}
	}
}

func receiverName(fn *ast.FuncDecl) string {
	if len(fn.Recv.List) == 0 {
		return ""
	}
	expr := fn.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if index, ok := expr.(*ast.IndexExpr); ok { // a generic receiver
		expr = index.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

func walkGo(t *testing.T, root string, fn func(path string, file *ast.File, isTest bool)) {
	t.Helper()

	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "node_modules" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		parsed, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		fn(path, parsed, strings.HasSuffix(path, "_test.go"))
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
}

func relative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}
