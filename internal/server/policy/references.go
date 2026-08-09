package policy

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// What a policy set names, and whether it is there.
//
// Cedar is default-deny, so a rule referring to a group that does not exist
// never matches — and a rule that never matches is indistinguishable, from the
// outside, from a rule working correctly and refusing. That asymmetry is why
// this file exists: the failure is silent in the safe direction, which means
// nobody finds it until someone who should have access does not have it, and by
// then the rule looks fine.
//
// It is not hypothetical. Cardinal's own shipped policy set spent its first
// release naming five group identifiers no migration created. Three of eleven
// rules — every rule governing SSH, sudo, and web access — were inert, and the
// file containing them carried a comment warning about exactly this.

// Reference is a directory entity a policy names.
type Reference struct {
	// Policy is the @id of the rule that names it, so a report can say where to
	// look rather than only what is missing.
	Policy string

	// Kind is the directory entity type: "group", "application", "host" or
	// "user". Deliberately the directory's vocabulary rather than Cedar's, so
	// resolving one does not require the store to know how Cedar spells things.
	Kind string

	// Identifier is a UUID for groups, hosts and users, and a name for
	// applications — matching what each decision point puts in the request.
	Identifier string
}

func (r Reference) String() string {
	return fmt.Sprintf("%s %s (in %s)", r.Kind, r.Identifier, r.Policy)
}

// cedarEntity matches an entity literal in rendered Cedar.
//
// Actions are excluded: they are a closed vocabulary defined in this package,
// not directory data, and UngovernedActions already reports one that no rule
// mentions.
var cedarEntity = regexp.MustCompile(
	`Cardinal::(Group|Application|Host|User)::"([^"]*)"`)

// kinds maps the Cedar type to the directory type.
var kinds = map[string]string{
	"Group":       "group",
	"Application": "application",
	"Host":        "host",
	"User":        "user",
}

// References lists every directory entity the loaded policy set names.
//
// Read from each policy's re-rendered Cedar rather than from the source text,
// which matters more than it sounds: the shipped policy file contains worked
// examples inside comments, and scanning the raw document would report those as
// missing entities every time. cedar-go drops comments when it renders a policy
// from its AST, so what is scanned here is only what the rule actually says.
//
// The one thing this cannot distinguish is an entity literal appearing inside a
// string, as in `context.path == "Cardinal::Group::\"x\""`. Nothing writes that,
// and the cost of being wrong is a spurious warning rather than a wrong
// decision.
func (e *Engine) References() []Reference {
	var out []Reference
	for id, p := range e.policies.All() {
		name := e.name(id)
		for _, m := range cedarEntity.FindAllStringSubmatch(string(p.MarshalCedar()), -1) {
			kind, ok := kinds[m[1]]
			if !ok {
				continue
			}
			out = append(out, Reference{Policy: name, Kind: kind, Identifier: m[2]})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Policy != out[j].Policy {
			return out[i].Policy < out[j].Policy
		}
		return out[i].Identifier < out[j].Identifier
	})
	return out
}

// Exists reports whether one referenced entity is in the directory.
//
// A function rather than a store handle because internal/store imports the
// claims package, which imports this one — so this package cannot import the
// store without a cycle. Passing the lookup in also means a test can answer
// without a database.
type Exists func(ctx context.Context, kind, identifier string) (bool, error)

// Dangling returns the references the directory does not have.
//
// Deduplicated by (kind, identifier) before lookup: the shipped set names
// env-dev twice, and asking the database the same question twice to print the
// same answer twice helps nobody.
func (e *Engine) Dangling(ctx context.Context, exists Exists) ([]Reference, error) {
	seen := map[string]bool{}
	var out []Reference

	for _, ref := range e.References() {
		key := ref.Kind + "\x00" + ref.Identifier
		if seen[key] {
			continue
		}
		seen[key] = true

		found, err := exists(ctx, ref.Kind, ref.Identifier)
		if err != nil {
			return nil, fmt.Errorf("policy: checking %s: %w", ref, err)
		}
		if !found {
			out = append(out, ref)
		}
	}
	return out, nil
}

// ExplainDangling renders the report for a person.
//
// Wordier than a list because the list on its own reads as pedantry — "group
// 0000…e5be1 not found" invites a shrug. What the reader needs is the
// consequence: the rule naming it is dead, and its deadness looks like it
// working.
func ExplainDangling(refs []Reference) string {
	if len(refs) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d reference(s) name something the directory does not have.\n",
		len(refs))
	fmt.Fprint(&b, "Cedar is default-deny, so each rule below never matches — "+
		"which looks exactly like it working.\n\n")
	for _, ref := range refs {
		fmt.Fprintf(&b, "  %s\n", ref)
	}
	return b.String()
}
