package scim

import (
	"fmt"
	"strings"
)

// Filters, and how little of the grammar is needed.
//
// RFC 7644 §3.4.2.2 defines a full expression language: and, or, not, grouping,
// nine operators, and paths into sub-attributes. Implementing all of it against
// a SQL directory is a project, and implementing it badly is worse than not
// implementing it — a filter silently misread returns the wrong people, and a
// provisioning client acts on the answer.
//
// What identity providers actually send during reconciliation is one equality
// on the resource's natural key:
//
//	userName eq "ada@example.com"
//	displayName eq "Engineering"
//	externalId eq "8f14e45f"
//
// So that is what this parses, exactly, and anything else is refused as
// unsupported rather than approximated. A client that gets a clear refusal
// falls back to listing and filtering itself; a client that gets a plausible
// wrong answer does not know to.

// Filter is a single equality on one attribute.
type Filter struct {
	Attribute string
	Value     string
}

// ErrUnsupportedFilter reports a filter this deliberately does not parse.
type ErrUnsupportedFilter struct{ Raw string }

func (e ErrUnsupportedFilter) Error() string {
	return fmt.Sprintf(
		"filter %q is not supported: this provider parses a single `attribute eq \"value\"` "+
			"and refuses anything else rather than approximating it", e.Raw)
}

// ParseFilter reads the one form that matters.
//
// Returns a nil filter and no error for an empty string, which is "list
// everything" and the commonest request of all.
func ParseFilter(raw string) (*Filter, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	// Split on the first run of spaces around `eq`, case-insensitively. Done by
	// hand rather than with a regular expression so the quoted value keeps
	// whatever is inside it: a display name may legitimately contain " eq ".
	lower := strings.ToLower(raw)
	idx := strings.Index(lower, " eq ")
	if idx < 0 {
		return nil, ErrUnsupportedFilter{Raw: raw}
	}

	attribute := strings.TrimSpace(raw[:idx])
	value := strings.TrimSpace(raw[idx+len(" eq "):])

	// Anything compound. Checked on the attribute side too, because
	// `a eq "x" and b eq "y"` splits at the first ` eq ` and would otherwise
	// look like a plain filter with a strange value.
	if strings.ContainsAny(attribute, " ()") {
		return nil, ErrUnsupportedFilter{Raw: raw}
	}

	unquoted, ok := unquote(value)
	if !ok {
		return nil, ErrUnsupportedFilter{Raw: raw}
	}

	return &Filter{Attribute: strings.ToLower(attribute), Value: unquoted}, nil
}

// unquote reads a SCIM string literal, and refuses anything after it.
//
// The refusal is what catches `userName eq "ada" and active eq true`: the
// closing quote is not the end of the input, so this is a compound filter
// wearing a simple one's clothes.
func unquote(v string) (string, bool) {
	if len(v) < 2 || v[0] != '"' {
		return "", false
	}

	var b strings.Builder
	for i := 1; i < len(v); i++ {
		switch v[i] {
		case '\\':
			if i+1 >= len(v) {
				return "", false
			}
			i++
			b.WriteByte(v[i])
		case '"':
			// Must be the last character. Anything after it is a conjunction,
			// a second clause, or something else this does not understand.
			if i != len(v)-1 {
				return "", false
			}
			return b.String(), true
		default:
			b.WriteByte(v[i])
		}
	}
	return "", false
}
