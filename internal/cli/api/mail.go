package api

import (
	"context"
)

// Notification email, as the API sees it.

// MailSettings is how this deployment sends.
//
// The relay password is never in it. Whether one is stored is a different
// question from what it is, and PasswordSet is the only part of it a settings
// view has any business knowing.
type MailSettings struct {
	Enabled     bool   `json:"enabled"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	FromAddress string `json:"fromAddress"`
	FromName    string `json:"fromName"`
	ReplyTo     string `json:"replyTo"`
	TLSMode     string `json:"tlsMode"`
	PasswordSet bool   `json:"passwordSet"`

	// Queued and Failing are the state of the outbox, which is the thing that
	// is otherwise invisible: a relay that stopped accepting mail looks exactly
	// like a quiet week.
	Queued  int `json:"queued"`
	Failing int `json:"failing"`
}

// MailSettingsRequest replaces the settings whole.
//
// Every field is sent, including the ones a caller did not mean to change, so
// anything editing one setting reads the current values first and sends them
// back. Password is the exception: empty leaves the stored one alone, because
// there is no way to send back what was never disclosed.
type MailSettingsRequest struct {
	Enabled     bool   `json:"enabled"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`
	FromAddress string `json:"fromAddress"`
	FromName    string `json:"fromName"`
	ReplyTo     string `json:"replyTo"`
	TLSMode     string `json:"tlsMode"`
}

// MailTemplate is one message, with the built-in wording alongside whatever
// this deployment replaced it with.
type MailTemplate struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Body    string `json:"body"`

	Overridden     bool   `json:"overridden"`
	BuiltInSubject string `json:"builtInSubject"`
	BuiltInBody    string `json:"builtInBody"`
}

// MailSettings reads how this deployment sends.
func (c *Client) MailSettings(ctx context.Context) (MailSettings, error) {
	var out MailSettings
	err := c.get(ctx, "/api/mail/settings", &out)
	return out, err
}

// SaveMailSettings replaces them.
func (c *Client) SaveMailSettings(ctx context.Context, req MailSettingsRequest) error {
	return c.put(ctx, "/api/mail/settings", req, nil)
}

// TestSend is what the relay did with one message.
//
// A refusal comes back as a 200 carrying Sent false and the relay's own words,
// not as an HTTP error: "550 user unknown" and "certificate signed by unknown
// authority" want completely different responses, and flattening either into a
// status code makes somebody go and find out which.
type TestSend struct {
	Sent  bool   `json:"sent"`
	Error string `json:"error"`
}

// SendTestMail sends one message now, to prove the relay accepts it. Directly
// rather than through the outbox, because the point is to see the answer.
func (c *Client) SendTestMail(ctx context.Context, to string) (TestSend, error) {
	var out TestSend
	err := c.post(ctx, "/api/mail/test", map[string]string{"to": to}, &out)
	return out, err
}

// MailTemplates lists every message Cardinal sends.
func (c *Client) MailTemplates(ctx context.Context) ([]MailTemplate, error) {
	var out struct {
		Templates []MailTemplate `json:"templates"`
	}
	err := c.get(ctx, "/api/mail/templates", &out)
	return out.Templates, err
}

// ResetMailTemplate discards an override, returning to the built-in wording.
func (c *Client) ResetMailTemplate(ctx context.Context, kind string) error {
	return c.del(ctx, "/api/mail/templates/"+escape(kind), nil)
}

// SaveMailTemplate replaces one message's wording.
func (c *Client) SaveMailTemplate(ctx context.Context, kind, subject, body string) error {
	return c.put(ctx, "/api/mail/templates/"+escape(kind),
		map[string]string{"subject": subject, "body": body}, nil)
}
