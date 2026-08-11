// Package lint holds checks on the source that are not about what it does.
package lint_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Comments are read by somebody who was not there.
//
// This codebase argues in its comments, which is deliberate and stays. What
// does not work is an argument that leans on something the reader cannot
// reach: a roadmap, a planning document, a conversation. "The plan says so" is
// authority nobody can weigh, and "once Cedar lands (Phase 2) this becomes a
// policy" was a promise that quietly expired — Cedar landed, the check is
// still hardcoded, and the comment described a plan nobody was executing.
//
// Enforced rather than written down for the same reason the expand-only rule
// is: the failure is silent, it arrives late, and by the time somebody notices
// the person who could explain what was meant has moved on.

// privateReferences are phrases that point outside the repository.
//
// Deliberately few and specific. A check that flagged every occurrence of
// "plan" would be turned off within a week, and a check people turn off is
// worse than no check.
var privateReferences = []struct {
	pattern *regexp.Regexp
	why     string
}{
	{
		regexp.MustCompile(`(?i)\bthe plan\b`),
		"names a document the reader does not have; say the reasoning instead",
	},
	{
		regexp.MustCompile(`\bPhase [0-9]`),
		"names a roadmap stage; say what the code does now, and what would have " +
			"to be decided for it to change",
	},
	{
		regexp.MustCompile(`(?i)\bas (we|i) (discussed|agreed|said)\b`),
		"points at a conversation the reader was not part of",
	},
	{
		regexp.MustCompile(`(?i)\byou asked\b|\bthe user (asked|wanted|said)\b`),
		"addresses somebody who is not the reader",
	},
}

func TestCommentsDoNotDependOnBeingThere(t *testing.T) {
	root := filepath.Join("..", "..")

	var findings []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "dist", "build", ".next":
				return filepath.SkipDir
			}
			return nil
		}
		// The ADRs and the changelog are records of decisions and are allowed
		// to name phases and plans — that is what they are for. This is about
		// comments in code, where the reader has no such context to hand.
		switch filepath.Ext(path) {
		case ".go", ".sql", ".ts", ".tsx":
		default:
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for n, line := range strings.Split(string(content), "\n") {
			trimmed := strings.TrimSpace(line)
			if !isComment(trimmed) {
				continue
			}
			// This file quotes the phrases it forbids.
			if strings.HasSuffix(path, filepath.Join("internal", "lint", "comments_test.go")) {
				continue
			}
			for _, ref := range privateReferences {
				if ref.pattern.MatchString(trimmed) {
					findings = append(findings,
						filepath.ToSlash(path)+":"+itoa(n+1)+"\n      "+trimmed+
							"\n      → "+ref.why)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) > 0 {
		t.Errorf("%d comment(s) depend on something the reader cannot reach:\n\n    %s\n",
			len(findings), strings.Join(findings, "\n    "))
	}
}

// isComment reports whether a trimmed line begins a comment in any of the
// languages walked above.
//
// Line-based on purpose: a check that parsed four grammars to notice a phrase
// would be a parser to maintain, and the phrases are what matter. The cost was
// measured rather than assumed — planting all four phrases in one wrapped
// comment caught three, because "the user asked" had been split across a line
// break. So this finds the careless case and not the determined one, which is
// the right trade for something whose real job is to keep a habit visible.
func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "--") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
