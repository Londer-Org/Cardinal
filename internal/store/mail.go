package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/directory/event"
)

// Notification email.
//
// Nothing here authorises anything, and that is the design rather than a first
// step. ADR 0009 is explicit that recovery email is "never for administrators,
// never alone", and requireDeviceBound exists so that only a passkey can change
// what authenticates as you — a mailed code able to do either would make
// whoever runs the mail server able to take over any account.
//
// So these messages say what happened. Their value is detection: somebody who
// receives "a passkey was added to your account" and did not add one has found
// out, which is worth a great deal and costs nothing in trust.

// ErrMailNotConfigured reports that no relay has been set up.
var ErrMailNotConfigured = errors.New("store: notification email is not configured")

// MailSettings is how this deployment sends.
type MailSettings struct {
	Enabled bool

	Host     string
	Port     int
	Username string

	// Password is present only when it has just been supplied or explicitly
	// read for sending. Everywhere else it is empty, so a settings page cannot
	// show it back and a log line cannot carry it.
	Password string

	FromAddress string
	FromName    string
	ReplyTo     string
	TLSMode     string

	UpdatedAt time.Time
}

// MailSettings reads how this deployment sends, without the password.
//
// The default for a page, a CLI listing and anything else that wants to know
// how mail is set up rather than to send with it. A caller that needs to send
// asks for the secret explicitly, which makes the two cases visible at every
// call site instead of one convenience returning both.
func (s *Store) MailSettings(ctx context.Context) (*MailSettings, error) {
	return s.mailSettings(ctx, false)
}

// MailSettingsWithPassword is for the sender, and only the sender.
func (s *Store) MailSettingsWithPassword(ctx context.Context, sealKey string) (*MailSettings, error) {
	settings, err := s.mailSettings(ctx, true)
	if err != nil {
		return nil, err
	}
	if settings.Password == "" {
		return settings, nil
	}
	sealer, err := newSealer(sealKey)
	if err != nil {
		return nil, err
	}
	plain, err := sealer.open([]byte(settings.Password))
	if err != nil {
		return nil, fmt.Errorf("store: opening the relay password: %w", err)
	}
	settings.Password = string(plain)
	return settings, nil
}

func (s *Store) mailSettings(ctx context.Context, withSecret bool) (*MailSettings, error) {
	var m MailSettings
	var sealed []byte
	err := s.pool.QueryRow(ctx, `
		SELECT enabled, host, port, username, password_sealed,
		       from_address, from_name, reply_to, tls_mode, updated_at
		  FROM mail_settings WHERE id`).
		Scan(&m.Enabled, &m.Host, &m.Port, &m.Username, &sealed,
			&m.FromAddress, &m.FromName, &m.ReplyTo, &m.TLSMode, &m.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// Never configured is not an error. It is the state every new
		// deployment is in, and the answer is "off" rather than a failure the
		// caller has to special-case.
		return &MailSettings{TLSMode: "starttls", Port: 587}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading mail settings: %w", err)
	}
	if withSecret {
		m.Password = string(sealed)
	}
	return &m, nil
}

// SaveMailSettings writes them, sealing the password.
//
// An empty password leaves whatever is stored alone, so saving a change to the
// from address does not silently blank the credential — which is what a form
// that always sends every field would otherwise do.
func (s *Store) SaveMailSettings(
	ctx context.Context, m MailSettings, sealKey string, actorID *uuid.UUID,
) error {
	var sealed []byte
	if m.Password != "" {
		sealer, err := newSealer(sealKey)
		if err != nil {
			return err
		}
		sealed, err = sealer.seal([]byte(m.Password))
		if err != nil {
			return err
		}
	}

	return s.InTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO mail_settings
			       (id, enabled, host, port, username, password_sealed,
			        from_address, from_name, reply_to, tls_mode, updated_at, updated_by)
			VALUES (true, $1, $2, $3, $4, $5, $6, $7, $8, $9, now(), $10)
			ON CONFLICT (id) DO UPDATE SET
			    enabled = excluded.enabled,
			    host = excluded.host,
			    port = excluded.port,
			    username = excluded.username,
			    -- Only when a new one was given.
			    password_sealed = coalesce(excluded.password_sealed,
			                               mail_settings.password_sealed),
			    from_address = excluded.from_address,
			    from_name = excluded.from_name,
			    reply_to = excluded.reply_to,
			    tls_mode = excluded.tls_mode,
			    updated_at = now(),
			    updated_by = excluded.updated_by`,
			m.Enabled, m.Host, m.Port, m.Username, sealed,
			m.FromAddress, m.FromName, m.ReplyTo, m.TLSMode, actorID)
		if err != nil {
			return fmt.Errorf("store: saving mail settings: %w", err)
		}

		ev, err := event.New(event.ActionMailSettingsChanged, nil, actorID,
			map[string]any{"enabled": m.Enabled})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// MailTemplate is a deployment's wording for one kind of message.
type MailTemplate struct {
	Kind      string
	Subject   string
	Body      string
	UpdatedAt time.Time
}

// MailTemplates lists the overrides a deployment has saved.
//
// Only the overrides. A kind absent here uses what the binary ships, so a
// deployment that has never edited a message gets improvements to it rather
// than a copy of whatever it said the day the database was made.
func (s *Store) MailTemplates(ctx context.Context) (map[string]MailTemplate, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT kind, subject, body, updated_at FROM mail_templates`)
	if err != nil {
		return nil, fmt.Errorf("store: reading mail templates: %w", err)
	}
	defer rows.Close()

	out := map[string]MailTemplate{}
	for rows.Next() {
		var t MailTemplate
		if err := rows.Scan(&t.Kind, &t.Subject, &t.Body, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out[t.Kind] = t
	}
	return out, rows.Err()
}

// SaveMailTemplate stores an override.
func (s *Store) SaveMailTemplate(ctx context.Context, t MailTemplate, actorID *uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO mail_templates (kind, subject, body, updated_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (kind) DO UPDATE SET
		    subject = excluded.subject,
		    body = excluded.body,
		    updated_at = now(),
		    updated_by = excluded.updated_by`,
		t.Kind, t.Subject, t.Body, actorID)
	if err != nil {
		return fmt.Errorf("store: saving mail template: %w", err)
	}
	return nil
}

// ResetMailTemplate removes an override, returning that kind to the built-in.
func (s *Store) ResetMailTemplate(ctx context.Context, kind string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM mail_templates WHERE kind = $1`, kind)
	if err != nil {
		return fmt.Errorf("store: resetting mail template: %w", err)
	}
	return nil
}

// Queued is one message waiting to go out.
type Queued struct {
	ID          uuid.UUID
	Recipient   string
	SubjectLine string
	Body        string
	Kind        string
	Attempts    int
}

// EnqueueMail adds a message to the outbox.
//
// Takes a transaction when the caller has one, so the notification and the
// change it describes commit together. Several callers do not — a passkey
// registration commits inside the auth service — and pass nil, which queues on
// the pool instead.
//
// The difference is worth stating plainly rather than pretending it away: with
// nil there is a window, between the change committing and this row being
// written, in which a process that dies loses the notice. That is acceptable
// here and would not be for anything that granted access. These messages report;
// a lost one costs somebody a notification, not their account.
func (s *Store) EnqueueMail(
	ctx context.Context, tx pgx.Tx,
	subjectID *uuid.UUID, recipient, kind, subjectLine, body string,
) error {
	const insert = `
		INSERT INTO mail_outbox (subject_id, recipient, kind, subject_line, body)
		VALUES ($1, $2, $3, $4, $5)`

	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, insert, subjectID, recipient, kind, subjectLine, body)
	} else {
		_, err = s.pool.Exec(ctx, insert, subjectID, recipient, kind, subjectLine, body)
	}
	if err != nil {
		return fmt.Errorf("store: queueing mail: %w", err)
	}
	return nil
}

// ClaimMail takes messages that are due, for one worker.
//
// FOR UPDATE SKIP LOCKED, so two servers can both run a sender and neither
// waits for the other or sends the same message twice. The row is claimed by
// moving its next attempt forward, which means a worker that dies mid-send
// leaves a message that retries rather than one that is stuck.
func (s *Store) ClaimMail(ctx context.Context, limit int) ([]Queued, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE mail_outbox SET
		    attempts = attempts + 1,
		    -- Moved forward before the attempt, not after it. A process that
		    -- dies mid-send has already released the row into the future
		    -- rather than leaving it claimed forever.
		    next_attempt_at = now() + (interval '1 minute' * least(attempts + 1, 30))
		 WHERE id IN (
		     SELECT id FROM mail_outbox
		      WHERE sent_at IS NULL AND next_attempt_at <= now()
		      ORDER BY next_attempt_at
		      LIMIT $1
		      FOR UPDATE SKIP LOCKED)
		RETURNING id, recipient, kind, subject_line, body, attempts`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: claiming mail: %w", err)
	}
	defer rows.Close()

	var out []Queued
	for rows.Next() {
		var q Queued
		if err := rows.Scan(&q.ID, &q.Recipient, &q.Kind,
			&q.SubjectLine, &q.Body, &q.Attempts); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// MailSent marks a message delivered.
func (s *Store) MailSent(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE mail_outbox SET sent_at = now(), last_error = NULL WHERE id = $1`, id)
	return err
}

// MailFailed records why, leaving the message to be retried.
//
// The relay's own words, kept rather than summarised. "550 5.1.1 user unknown"
// and "connection refused" want completely different responses, and a queue
// that says only "failed" makes somebody go and reproduce it.
func (s *Store) MailFailed(ctx context.Context, id uuid.UUID, reason string) error {
	if len(reason) > 500 {
		reason = reason[:500]
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE mail_outbox SET last_error = $2 WHERE id = $1`, id, reason)
	return err
}

// PendingMail counts what is waiting, for the console and for `cardinal mail
// status`.
func (s *Store) PendingMail(ctx context.Context) (pending, failing int, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE sent_at IS NULL),
		       count(*) FILTER (WHERE sent_at IS NULL AND attempts > 3)
		  FROM mail_outbox`).Scan(&pending, &failing)
	if err != nil {
		return 0, 0, fmt.Errorf("store: counting queued mail: %w", err)
	}
	return pending, failing, nil
}
