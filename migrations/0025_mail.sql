-- Notification email: settings, templates, and an outbox.
--
-- In the database rather than the configuration file, which is a departure from
-- how everything else here is configured and a deliberate one. A deployment
-- running the published image cannot edit files inside it, and changing which
-- relay to use or rewording a message should not require rebuilding a container.
--
-- The line is not "file versus database" — it is whether a setting protects the
-- system. The DSN, the listen address and the encryption keys stay in the file
-- because they are what the system trusts. A relay hostname and the wording of
-- a message are operational content, and belong where they can be edited.
--
-- Nothing here authorises anything (ADR 0009). These messages say what happened;
-- a compromised mail server therefore reads news rather than gaining access.

-- One row, and the constraint says so.
--
-- A settings table that permits two rows eventually has two, and then the
-- question of which one is live is answered differently by whoever wrote the
-- query last.
CREATE TABLE mail_settings (
    id            boolean     PRIMARY KEY DEFAULT true CHECK (id),

    enabled       boolean     NOT NULL DEFAULT false,

    host          text        NOT NULL DEFAULT '',
    port          integer     NOT NULL DEFAULT 587,
    username      text        NOT NULL DEFAULT '',

    -- Sealed with the same AEAD the certificate authorities use, keyed from
    -- mail.encryption_key in the configuration file. A database read must not
    -- yield a working relay credential, for the same reason it must not yield
    -- a signing key — and the key living in the file is what makes an attacker
    -- need two things rather than one.
    password_sealed bytea,

    -- Who the message is from, and where a reply goes. Separate because the
    -- envelope sender is often a no-reply address while a human should still be
    -- reachable.
    from_address  text        NOT NULL DEFAULT '',
    from_name     text        NOT NULL DEFAULT '',
    reply_to      text        NOT NULL DEFAULT '',

    -- StartTLS by default. Refusing to send in the clear is the safe default,
    -- and a relay on localhost that genuinely has no TLS is the exception that
    -- has to be stated.
    tls_mode      text        NOT NULL DEFAULT 'starttls'
                              CHECK (tls_mode IN ('starttls', 'tls', 'none')),

    updated_at    timestamptz NOT NULL DEFAULT now(),
    updated_by    uuid        REFERENCES entities(id)
);

-- Templates, one row per kind of message, overriding what the binary ships.
--
-- Absent means "use the built-in", which is why there is no seeding here: a
-- deployment that has never touched a template gets whatever the current
-- version of Cardinal says, including improvements to it, rather than a copy of
-- whatever it said the day the database was created.
CREATE TABLE mail_templates (
    kind          text        PRIMARY KEY,

    subject       text        NOT NULL,
    body          text        NOT NULL,

    updated_at    timestamptz NOT NULL DEFAULT now(),
    updated_by    uuid        REFERENCES entities(id)
);

-- The outbox.
--
-- Queued here and delivered by a worker, so that nothing a person does waits on
-- a mail server. A relay that is slow, down, or greylisting must delay a
-- notification and never fail the passkey registration that caused it — the
-- action already happened, and refusing it afterwards because an email did not
-- go would be inventing a failure.
CREATE TABLE mail_outbox (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),

    -- Who it concerns, for the journal and for "stop mailing this account".
    -- Nullable because an invitation may go to somebody who is not an entity
    -- yet.
    subject_id    uuid        REFERENCES entities(id) ON DELETE SET NULL,

    recipient     text        NOT NULL,
    kind          text        NOT NULL,
    subject_line  text        NOT NULL,
    body          text        NOT NULL,

    created_at    timestamptz NOT NULL DEFAULT now(),

    -- When it may next be attempted. Backoff moves it forward rather than
    -- sleeping a worker, so a queue of failing messages does not hold up the
    -- ones behind them.
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    attempts      integer     NOT NULL DEFAULT 0,

    sent_at       timestamptz,

    -- The last thing the relay said, kept so somebody debugging a queue can see
    -- why rather than guessing. Not the message body, which is already here.
    last_error    text
);

-- The claim query: unsent, due, oldest first.
CREATE INDEX mail_outbox_due_idx
    ON mail_outbox (next_attempt_at)
    WHERE sent_at IS NULL;
