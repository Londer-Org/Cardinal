package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Relay is how to reach a mail server.
type Relay struct {
	Host     string
	Port     int
	Username string
	Password string

	FromAddress string
	FromName    string
	ReplyTo     string

	// TLSMode is "starttls", "tls" or "none".
	TLSMode string
}

// Message is one rendered mail.
type Message struct {
	To      string
	Subject string
	Body    string
}

// ErrNotConfigured reports a relay with nowhere to send.
var ErrNotConfigured = errors.New("mail: no relay host is configured")

// Send delivers one message.
//
// Synchronous and single-shot: retrying is the outbox's job, and a sender that
// retried internally would hold a worker while the queue behind it waited.
//
// The relay's own words come back on failure. "550 5.1.1 user unknown" and
// "connection refused" want completely different responses, and a queue that
// records only "failed" makes somebody reproduce it by hand to find out which.
func Send(ctx context.Context, relay Relay, msg Message) error {
	if relay.Host == "" {
		return ErrNotConfigured
	}
	if _, err := mail.ParseAddress(msg.To); err != nil {
		// Refused here rather than by the relay, because a bad address is a
		// permanent failure and there is no point spending thirty retries
		// discovering it.
		return fmt.Errorf("mail: %q is not an address: %w", msg.To, err)
	}

	address := net.JoinHostPort(relay.Host, strconv.Itoa(relay.Port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	var conn net.Conn
	var err error
	switch relay.TLSMode {
	case "tls":
		// Implicit TLS, usually 465. The handshake happens before anything is
		// said, so there is no plaintext phase to strip.
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{ServerName: relay.Host, MinVersion: tls.VersionTLS12},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", address)
	default:
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("mail: reaching %s: %w", address, err)
	}
	defer conn.Close() //nolint:errcheck // best effort; the meaningful error is the one being returned

	client, err := smtp.NewClient(conn, relay.Host)
	if err != nil {
		return fmt.Errorf("mail: greeting %s: %w", address, err)
	}
	defer client.Close() //nolint:errcheck // as above

	if relay.TLSMode == "starttls" {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			// Refused rather than downgraded. A relay that was configured for
			// STARTTLS and does not offer it is either misconfigured or being
			// stripped, and continuing would send the credential and the
			// message in the clear to find out which.
			return errors.New("mail: the relay does not offer STARTTLS, and this " +
				"deployment is configured to require it — set tls_mode to 'none' " +
				"only if the relay is genuinely local")
		}
		if tlsErr := client.StartTLS(&tls.Config{
			ServerName: relay.Host, MinVersion: tls.VersionTLS12,
		}); tlsErr != nil {
			return fmt.Errorf("mail: starting TLS with %s: %w", address, tlsErr)
		}
	}

	if relay.Username != "" {
		// smtp.PlainAuth refuses to send credentials over an unencrypted
		// connection unless the host is localhost. That check is kept rather
		// than worked around: it is the standard library declining to leak a
		// password, and a deployment that needs it relaxed has a relay problem
		// rather than a Cardinal problem.
		auth := smtp.PlainAuth("", relay.Username, relay.Password, relay.Host)
		if authErr := client.Auth(auth); authErr != nil {
			return fmt.Errorf("mail: authenticating to %s: %w", address, authErr)
		}
	}

	from := relay.FromAddress
	if from == "" {
		return errors.New("mail: no from address is configured")
	}
	if fromErr := client.Mail(from); fromErr != nil {
		return fmt.Errorf("mail: MAIL FROM %s: %w", from, fromErr)
	}
	if rcptErr := client.Rcpt(msg.To); rcptErr != nil {
		return fmt.Errorf("mail: RCPT TO %s: %w", msg.To, rcptErr)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("mail: DATA: %w", err)
	}
	if _, writeErr := w.Write([]byte(compose(relay, msg))); writeErr != nil {
		return fmt.Errorf("mail: writing the message: %w", writeErr)
	}
	if closeErr := w.Close(); closeErr != nil {
		// The relay's verdict arrives here, at the end of DATA, which is where
		// "message rejected" comes from rather than from any earlier step.
		return fmt.Errorf("mail: the relay refused the message: %w", closeErr)
	}
	return client.Quit()
}

// compose builds the RFC 5322 message.
//
// Headers assembled here rather than taken from a template, so that no wording
// a deployment can edit is able to introduce one. A subject containing a newline
// would otherwise let somebody append Bcc to every message this system sends.
func compose(relay Relay, msg Message) string {
	var b strings.Builder

	from := relay.FromAddress
	if relay.FromName != "" {
		from = (&mail.Address{Name: relay.FromName, Address: relay.FromAddress}).String()
	}

	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", msg.To)
	if relay.ReplyTo != "" {
		fmt.Fprintf(&b, "Reply-To: %s\r\n", relay.ReplyTo)
	}
	fmt.Fprintf(&b, "Subject: %s\r\n", header(msg.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")

	// So a mailbox does not thread six months of security notices into one
	// conversation the recipient stops reading.
	b.WriteString("Auto-Submitted: auto-generated\r\n")

	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(msg.Body, "\n", "\r\n"))
	return b.String()
}

// header makes a value safe to put in one.
//
// Newlines removed, not escaped. A header is a line, so anything containing a
// break is either a mistake or somebody appending headers of their own — and
// there is no rendering of "Bcc: attacker@example" that belongs in a subject.
func header(v string) string {
	// CRLF first, so the usual pairing collapses to one space rather than two.
	v = strings.ReplaceAll(v, "\r\n", " ")
	v = strings.ReplaceAll(v, "\r", " ")
	v = strings.ReplaceAll(v, "\n", " ")
	return strings.TrimSpace(v)
}
