package mail

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/store"
)

// Notifier queues messages, and knows when not to.
type Notifier struct {
	store      *store.Store
	consoleURL string
	product    string
	log        *slog.Logger
}

// NewNotifier builds one.
func NewNotifier(s *store.Store, consoleURL, product string, log *slog.Logger) *Notifier {
	if product == "" {
		product = "Cardinal"
	}
	return &Notifier{store: s, consoleURL: consoleURL, product: product, log: log}
}

// Notify queues a message about something that happened to an account.
//
// Takes the transaction that caused the event where the caller has one, so the
// two commit together; nil is allowed, and several callers pass it because the
// change commits somewhere they do not control. See store.EnqueueMail for what
// that costs.
//
// Silent when there is no address or mail is off. A missing email is the
// ordinary state of a service account, and it must not turn registering a
// passkey into an error.
func (n *Notifier) Notify(
	ctx context.Context, tx pgx.Tx,
	subjectID *uuid.UUID, recipient, login string, kind Kind, url string,
) {
	if recipient == "" {
		return
	}

	settings, err := n.store.MailSettings(ctx)
	if err != nil || !settings.Enabled {
		return
	}

	var override *Template
	if saved, listErr := n.store.MailTemplates(ctx); listErr == nil {
		if t, ok := saved[string(kind)]; ok {
			override = &Template{Subject: t.Subject, Body: t.Body}
		}
	}

	subject, body, err := Render(kind, override, Data{
		Product:    n.product,
		Login:      login,
		When:       time.Now().Format(time.RFC1123),
		ConsoleURL: n.consoleURL,
		URL:        url,
	})
	if err != nil {
		// A template a deployment edited into something that will not render.
		// Logged and dropped: the alternative is failing the passkey
		// registration that caused it, and a broken template must not be able
		// to stop people managing their credentials.
		n.log.ErrorContext(ctx, "a mail template would not render, so no notice was sent",
			"kind", kind, "error", err)
		return
	}

	if err := n.store.EnqueueMail(ctx, tx, subjectID, recipient, string(kind), subject, body); err != nil {
		n.log.ErrorContext(ctx, "queueing a notification failed", "kind", kind, "error", err)
	}
}

// Deliver sends whatever is due, once.
//
// Returns how many went out, so a caller can log something useful and a test can
// assert on it rather than sleeping.
func (n *Notifier) Deliver(ctx context.Context, sealKey string, limit int) (int, error) {
	settings, err := n.store.MailSettingsWithPassword(ctx, sealKey)
	if err != nil {
		return 0, err
	}
	if !settings.Enabled || settings.Host == "" {
		return 0, nil
	}

	queued, err := n.store.ClaimMail(ctx, limit)
	if err != nil {
		return 0, err
	}

	relay := Relay{
		Host: settings.Host, Port: settings.Port,
		Username: settings.Username, Password: settings.Password,
		FromAddress: settings.FromAddress, FromName: settings.FromName,
		ReplyTo: settings.ReplyTo, TLSMode: settings.TLSMode,
	}

	sent := 0
	for _, q := range queued {
		err := Send(ctx, relay, Message{To: q.Recipient, Subject: q.SubjectLine, Body: q.Body})
		if err != nil {
			// Recorded, not retried here. The row's next attempt has already
			// been moved forward, so the queue behind it keeps moving.
			n.log.WarnContext(ctx, "sending a notification failed; it will be retried",
				"kind", q.Kind, "attempts", q.Attempts, "error", err)
			if markErr := n.store.MailFailed(ctx, q.ID, err.Error()); markErr != nil {
				n.log.ErrorContext(ctx, "recording a mail failure failed", "error", markErr)
			}
			continue
		}
		if err := n.store.MailSent(ctx, q.ID); err != nil {
			// Sent and not recorded, which means it will be sent again. Noisy
			// on purpose: a duplicate security notice is survivable and a
			// silent one is how somebody stops trusting the whole channel.
			n.log.ErrorContext(ctx, "a notification was sent and could not be marked sent; "+
				"it will be delivered again", "id", q.ID, "error", err)
			continue
		}
		sent++
	}
	return sent, nil
}
