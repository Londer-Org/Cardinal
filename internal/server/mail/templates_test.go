package mail_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/server/mail"
)

// TestEveryMessageSaysWhatToDoIfItWasNotYou.
//
// The reason to send any of these. A notification that somebody's credentials
// changed is worth nothing if the person reading it cannot tell what to do
// about it, and "if this was not you" is the sentence the whole exercise exists
// to deliver.
func TestEveryMessageSaysWhatToDoIfItWasNotYou(t *testing.T) {
	data := mail.Data{Login: "alice", When: "today", ConsoleURL: "https://id.example", URL: "https://id.example/enroll?token=x"}

	for _, kind := range mail.Kinds() {
		if kind == mail.KindTest {
			continue // it is a test message; there is no "you" involved
		}
		t.Run(string(kind), func(t *testing.T) {
			_, body, err := mail.Render(kind, nil, data)
			require.NoError(t, err)
			assert.Contains(t, strings.ToLower(body), "not you",
				"this message tells somebody their credentials changed and does not "+
					"say what to do if they did not do it")
		})
	}
}

// TestTheSignatureCannotBeEditedAway.
//
// A deployment may reword any message, which is the point of overrides — and it
// may not remove what identifies the sender and the account. A message that
// could be made unattributable is a phishing template with this deployment's
// own relay behind it.
func TestTheSignatureCannotBeEditedAway(t *testing.T) {
	hostile := mail.Template{
		Subject: "Urgent: verify your account",
		Body:    "Click here immediately: https://not-cardinal.example/steal",
	}

	_, body, err := mail.Render(mail.KindPasskeyRegistered, &hostile,
		mail.Data{Product: "Example Identity", Login: "alice", ConsoleURL: "https://id.example"})
	require.NoError(t, err)

	assert.Contains(t, body, "Sent by Example Identity")
	assert.Contains(t, body, "regarding the account alice")
	assert.Contains(t, body, "https://id.example")
}

// TestATemplateCannotReachForSomethingItWasNotGiven.
//
// missingkey=error, so a template naming a field that does not exist fails at
// render rather than sending a message with "<no value>" where a name should
// be — which is both useless and a small information leak about the shape of
// the data.
func TestATemplateCannotReachForSomethingItWasNotGiven(t *testing.T) {
	_, _, err := mail.Render(mail.KindTest,
		&mail.Template{Subject: "hi", Body: "{{.Password}}"}, mail.Data{Login: "alice"})
	assert.Error(t, err)
}
