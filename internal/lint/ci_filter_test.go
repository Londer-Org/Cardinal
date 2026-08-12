package lint_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The filter that decides whether the tests run.
//
// CI skips jobs a change cannot affect, which is worth doing and is a strange
// thing to leave untested: it is the one piece of the pipeline whose failure
// mode is a green tick on something nobody checked. So it gets the same
// treatment as anything else that can silently say no.
//
// Two of the cases below are the reason this exists rather than a `paths-ignore`
// on the workflow. `docs/schema.md` looks like documentation and is compared
// against the live schema by a Go test. A `.tsx` file looks like frontend and is
// walked by the comment check in this package. Both would be skipped by the
// obvious filter, and both would skip a test that can fail.

func TestTheCIFilterRunsWhatAChangeCanAffect(t *testing.T) {
	script := filepath.Join("..", "..", ".github", "scripts", "changed-areas.sh")

	for _, tc := range []struct {
		name   string
		files  []string
		expect map[string]bool
	}{
		{
			name:  "documentation alone needs nothing",
			files: []string{"README.md", "docs/adr/0033-the-cli-signs-in.md", "CHANGELOG.md"},
			expect: map[string]bool{
				"go": false, "frontend": false, "image": false, "e2e": false,
			},
		},
		{
			name:  "the generated schema document is a Go test",
			files: []string{"docs/schema.md"},
			expect: map[string]bool{
				"go": true, "frontend": false, "image": false, "e2e": false,
			},
		},
		{
			name:  "a frontend file is also walked by the comment check",
			files: []string{"web/src/views/policy.tsx"},
			expect: map[string]bool{
				"go": true, "frontend": true, "image": true, "e2e": true,
			},
		},
		{
			name:  "a migration reaches everything that builds a database",
			files: []string{"migrations/0034_partition_runway.sql"},
			expect: map[string]bool{
				"go": true, "frontend": false, "image": true, "e2e": true,
			},
		},
		{
			name:  "the example stack is only end-to-end",
			files: []string{"examples/compose.yml"},
			expect: map[string]bool{
				"go": false, "frontend": false, "image": false, "e2e": true,
			},
		},
		{
			name:  "Go changes everything except the frontend's own build",
			files: []string{"internal/store/partitions.go"},
			expect: map[string]bool{
				"go": true, "frontend": false, "image": true, "e2e": true,
			},
		},
		{
			name:  "a change to CI is exercised by all of CI",
			files: []string{".github/workflows/ci.yml", "README.md"},
			expect: map[string]bool{
				"go": true, "frontend": true, "image": true, "e2e": true,
			},
		},
		{
			name:  "so is a change to this filter",
			files: []string{".github/scripts/changed-areas.sh"},
			expect: map[string]bool{
				"go": true, "frontend": true, "image": true, "e2e": true,
			},
		},
		{
			name:  "the linter configuration is a Go change",
			files: []string{".golangci.yml"},
			expect: map[string]bool{
				"go": true, "frontend": false, "image": false, "e2e": false,
			},
		},
		{
			name:  "nothing changed",
			files: []string{},
			expect: map[string]bool{
				"go": false, "frontend": false, "image": false, "e2e": false,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "sh", script)
			cmd.Stdin = strings.NewReader(strings.Join(tc.files, "\n") + "\n")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("running the filter: %v\n%s", err, out)
			}

			got := map[string]bool{}
			for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
				key, value, ok := strings.Cut(line, "=")
				if !ok {
					t.Fatalf("the filter printed %q, which is not key=value", line)
				}
				got[key] = value == "true"
			}

			for area, want := range tc.expect {
				if got[area] != want {
					t.Errorf("%s: got %v, want %v\n  changed: %v\n  full output:\n%s",
						area, got[area], want, tc.files, out)
				}
			}
		})
	}
}
