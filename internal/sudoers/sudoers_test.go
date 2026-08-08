package sudoers_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.londer.be/cardinal/internal/sudoers"
)

var generated = time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

func requireVisudo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("visudo"); err != nil {
		// Skipped rather than faked. A stub validator would make these tests
		// pass on a machine where the real thing would reject the file, which
		// is the only outcome worse than not running them.
		t.Skip("visudo is not installed; run `make verify-sudoers` for the real check")
	}
}

// TestRenderedFileIsAcceptedByVisudo.
//
// The one assertion that matters. Everything else here is about *what* is
// written; this is about whether sudo will read it — and a file it will not read
// stops sudo working for everybody on the machine, including root.
func TestRenderedFileIsAcceptedByVisudo(t *testing.T) {
	requireVisudo(t)

	content, err := sudoers.Render([]string{"alice", "bob"}, "web-01.prod", generated)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "50-cardinal")
	if err := os.WriteFile(path, content, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := sudoers.Validate(t.Context(), path); err != nil {
		t.Fatalf("visudo rejected our own output:\n%s\n%v", content, err)
	}
}

// TestEmptyRenderIsStillValid.
//
// "Nobody may sudo here" is a legitimate answer and has to produce a file sudo
// accepts — an invalid one would take the whole machine's sudo down as the
// consequence of a correct policy decision.
func TestEmptyRenderIsStillValid(t *testing.T) {
	requireVisudo(t)

	content, err := sudoers.Render(nil, "web-01.prod", generated)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "Nobody in the directory") {
		t.Fatalf("an empty render must say so rather than be blank:\n%s", content)
	}

	path := filepath.Join(t.TempDir(), "50-cardinal")
	if err := os.WriteFile(path, content, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := sudoers.Validate(t.Context(), path); err != nil {
		t.Fatalf("visudo rejected the empty file: %v", err)
	}
}

// TestUnsafeNamesAreRefused.
//
// A sudoers file is line-oriented and unquoted, so a name with a newline in it
// is not a rendering problem, it is an injection. The directory does not
// constrain names to a POSIX alphabet, which is why this is checked rather than
// assumed.
func TestUnsafeNamesAreRefused(t *testing.T) {
	for _, name := range []string{
		"alice bob",
		"alice\nroot ALL=(ALL) NOPASSWD: ALL",
		"alice,bob",
		"ALL",
		"",
		"-alice",
		"alice$",
		strings.Repeat("a", 33),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sudoers.Render([]string{name}, "web-01.prod", generated)
			if err == nil {
				t.Fatalf("%q was rendered into a sudoers file", name)
			}
		})
	}
}

// TestOneUnsafeNameRefusesTheWholeFile.
//
// Rather than skipping it. Skipping silently removes somebody's sudo, and an
// unrenderable name means either a bug upstream or somebody trying something —
// neither is a case for carrying on with a partial file.
func TestOneUnsafeNameRefusesTheWholeFile(t *testing.T) {
	_, err := sudoers.Render([]string{"alice", "bad name", "bob"}, "web-01.prod", generated)
	if err == nil {
		t.Fatal("the file was rendered despite an unsafe name")
	}
	if !strings.Contains(err.Error(), "bad name") {
		t.Fatalf("the error does not say which name: %v", err)
	}
}

// TestRenderIsDeterministic.
//
// Same input, same bytes — so a refresh that changes nothing rewrites nothing
// meaningful, and a diff between two hosts is about policy rather than map
// iteration order.
func TestRenderIsDeterministic(t *testing.T) {
	first, err := sudoers.Render([]string{"bob", "alice", "carol"}, "web-01.prod", generated)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sudoers.Render([]string{"carol", "alice", "bob"}, "web-01.prod", generated)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("order changed the output:\n%s\n---\n%s", first, second)
	}
	if strings.Count(string(first), "alice ALL=") != 1 {
		t.Fatalf("alice appears more than once:\n%s", first)
	}
}

// TestInstallRefusesAnInvalidFileAndKeepsTheOldOne.
//
// The failure this package exists to prevent, and the assertion that proves the
// order is right: validate the candidate, and only then replace. A machine whose
// sudoers.d contains a broken file needs console access to recover.
func TestInstallRefusesAnInvalidFileAndKeepsTheOldOne(t *testing.T) {
	requireVisudo(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "50-cardinal")

	good, err := sudoers.Render([]string{"alice"}, "web-01.prod", generated)
	if err != nil {
		t.Fatal(err)
	}
	if installErr := sudoers.Install(t.Context(), path, good); installErr != nil {
		t.Fatal(installErr)
	}

	// Not something Render can produce — which is the point. This is the
	// belt-and-braces case: if a future change ever emits something visudo
	// dislikes, Install must still refuse it.
	if installErr := sudoers.Install(t.Context(), path, []byte("this is not sudoers syntax at all\n")); installErr == nil {
		t.Fatal("an invalid file was installed")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(good) {
		t.Fatalf("the previous file was replaced by a rejected one:\n%s", after)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("a candidate file was left behind: %v", entries)
	}
}

// TestInstalledFileIsNotGroupOrWorldWritable.
//
// sudo refuses to read a file anyone but its owner can write, and reports it as
// a syntax problem — so getting this wrong fails validation for a reason that
// reads as completely unrelated.
func TestInstalledFileIsNotGroupOrWorldWritable(t *testing.T) {
	requireVisudo(t)

	path := filepath.Join(t.TempDir(), "50-cardinal")
	content, err := sudoers.Render([]string{"alice"}, "web-01.prod", generated)
	if err != nil {
		t.Fatal(err)
	}
	if installErr := sudoers.Install(t.Context(), path, content); installErr != nil {
		t.Fatal(installErr)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		t.Fatalf("mode %o is writable beyond its owner", mode)
	}
}

// TestIncludeDirIsRecognisedInBothSpellings.
//
// `#includedir` looks like a comment and is not — it is what every distribution
// still ships. A check that understood only `@includedir` would report a
// perfectly working system as broken.
func TestIncludeDirIsRecognisedInBothSpellings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{"modern", "Defaults env_reset\n@includedir /etc/sudoers.d\n", true},
		{"traditional", "Defaults env_reset\n#includedir /etc/sudoers.d\n", true},
		{"indented", "  @includedir /etc/sudoers.d  \n", true},
		{"a different directory", "@includedir /etc/sudoers.local.d\n", false},
		{"absent", "Defaults env_reset\n", false},
		{"a real comment", "# @includedir /etc/sudoers.d is not enabled\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sudoers")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := sudoers.IncludeDirConfigured(path, "/etc/sudoers.d")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v for %q", got, tc.want, tc.content)
			}
		})
	}
}

// TestNothingOutsideTheDropInIsTouched.
//
// The break-glass rule, asserted structurally: the package is given one path and
// writes one path. A neighbouring drop-in and the main file are still there and
// unchanged afterwards, so nothing Cardinal does can take away an account's
// existing root.
func TestNothingOutsideTheDropInIsTouched(t *testing.T) {
	requireVisudo(t)

	dir := t.TempDir()
	neighbour := filepath.Join(dir, "10-local-admins")
	local := "localadmin ALL=(ALL:ALL) ALL\n"
	if err := os.WriteFile(neighbour, []byte(local), 0o440); err != nil {
		t.Fatal(err)
	}

	content, err := sudoers.Render([]string{"alice"}, "web-01.prod", generated)
	if err != nil {
		t.Fatal(err)
	}
	if installErr := sudoers.Install(t.Context(), filepath.Join(dir, "50-cardinal"), content); installErr != nil {
		t.Fatal(installErr)
	}

	after, err := os.ReadFile(neighbour)
	if err != nil {
		t.Fatalf("the neighbouring drop-in is gone: %v", err)
	}
	if string(after) != local {
		t.Fatalf("the neighbouring drop-in was modified:\n%s", after)
	}
}
