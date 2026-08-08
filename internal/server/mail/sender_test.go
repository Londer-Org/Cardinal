package mail

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestASubjectCannotSmuggleHeaders.
//
// Templates are editable by a deployment, and a subject is a header. Without
// stripping breaks, somebody able to edit a template could append a Bcc to
// every notification this system sends — from the deployment's own relay, past
// its own SPF.
func TestASubjectCannotSmuggleHeaders(t *testing.T) {
	out := compose(
		Relay{FromAddress: "id@example.com"},
		Message{
			To:      "alice@example.com",
			Subject: "Hello\r\nBcc: attacker@example.invalid",
			Body:    "body",
		},
	)

	// The text survives as text — flattened onto the subject line, where it is
	// visible and harmless. What must not exist is a *line* that is a Bcc
	// header, which is what an unescaped newline would have produced.
	headers, body, found := strings.Cut(out, "\r\n\r\n")
	assert.True(t, found)
	for _, line := range strings.Split(headers, "\r\n") {
		assert.False(t, strings.HasPrefix(strings.ToLower(line), "bcc:"),
			"a newline in the subject became a header of its own: %q", line)
	}
	assert.Contains(t, headers, "Subject: Hello Bcc: attacker@example.invalid")
	assert.Equal(t, 1, strings.Count(headers, "Subject:"))
	assert.Contains(t, body, "body")
}

// TestABodyCannotEndTheHeaders.
//
// The other direction: a body is written after the blank line, so nothing in it
// can be read as a header — but the line endings have to be right, or a relay
// that is strict about CRLF rejects everything this deployment sends.
func TestABodyCannotEndTheHeaders(t *testing.T) {
	out := compose(
		Relay{FromAddress: "id@example.com"},
		Message{To: "alice@example.com", Subject: "Subject", Body: "line one\nline two"},
	)
	assert.Contains(t, out, "line one\r\nline two")
	assert.NotContains(t, out, "line one\nline two")
}

// TestTheFromNameIsQuotedProperly.
//
// A display name containing a comma is ordinary — "Example, Inc." — and an
// unquoted one turns a single address into two, so half the messages go to a
// recipient that does not exist.
func TestTheFromNameIsQuotedProperly(t *testing.T) {
	out := compose(
		Relay{FromAddress: "id@example.com", FromName: "Example, Inc. Identity"},
		Message{To: "alice@example.com", Subject: "s", Body: "b"},
	)
	assert.Contains(t, out, `From: "Example, Inc. Identity" <id@example.com>`)
}
