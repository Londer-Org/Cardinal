-- Cardinal 0030: telling applications when access changes.
--
-- Revoking a session here ends it here. An application that issued its own
-- session from an OIDC login learns nothing until its token expires, which is
-- fifteen minutes at best and a refresh cycle at worst — so "signed out
-- everywhere" is true of Cardinal and not of the things Cardinal signed you
-- into. For a compromised account that gap is the whole incident.
--
-- The Shared Signals Framework closes it by pushing a signed statement of what
-- happened to whoever is listening. CAEP names the events; RFC 8417 is the
-- token; RFC 8935 is the delivery.

CREATE TABLE ssf_streams (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    -- The receiver, which is an application already registered here. A stream
    -- to something Cardinal has never heard of would be an outbound connection
    -- to an arbitrary URL configured in a database, which is a different and
    -- worse thing than a delivery to a known relying party.
    entity_id uuid NOT NULL REFERENCES oidc_clients(entity_id),

    -- Where to POST. Its own column rather than derived from a redirect URI:
    -- a receiving endpoint is not a browser destination and conflating them
    -- would mean an application could not have one without the other.
    endpoint text NOT NULL,

    -- Which events this receiver asked for. A stream that receives everything
    -- tells an application about people it has never seen, which is a directory
    -- leak dressed as a feature.
    events text[] NOT NULL DEFAULT '{}',

    -- Paused rather than deleted, so a receiver that is down does not lose its
    -- configuration and an operator can stop delivery without forgetting what
    -- it was.
    enabled boolean NOT NULL DEFAULT true,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid REFERENCES entities(id),

    CONSTRAINT ssf_streams_endpoint_is_https CHECK (endpoint LIKE 'https://%'),

    -- One stream per receiver. Two would mean every event delivered twice, and
    -- a receiver cannot tell a duplicate from a repeat.
    CONSTRAINT ssf_streams_one_per_receiver UNIQUE (entity_id)
);

COMMENT ON TABLE ssf_streams IS
    'Receivers Cardinal pushes security events to. Configured by an '
    'administrator rather than by the receiver: stream management over the '
    'API is not implemented, and the SSF configuration document says so.';

-- The outbox.
--
-- Same shape as mail_outbox and for the same reasons: claimed with FOR UPDATE
-- SKIP LOCKED so two servers can both deliver and neither waits, and the next
-- attempt moved forward before the attempt rather than after, so a process that
-- dies mid-send leaves a row that retries rather than one that is stuck.
CREATE TABLE ssf_events (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    stream_id uuid NOT NULL REFERENCES ssf_streams(id),

    -- Who it is about. Nullable because a stream-level event — verification —
    -- is about the stream rather than a person.
    subject_id uuid REFERENCES entities(id),

    event_type text NOT NULL,

    -- The signed token, built and signed when the event happened.
    --
    -- Signed at enqueue rather than at delivery so `iat` says when access
    -- actually changed. A receiver deciding how to treat a five-minute-old
    -- revocation needs that to be the truth rather than the time a retry
    -- happened to succeed.
    token text NOT NULL,

    created_at     timestamptz NOT NULL DEFAULT now(),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    attempts       int NOT NULL DEFAULT 0,
    delivered_at   timestamptz,
    last_error     text
);

CREATE INDEX ssf_events_pending_idx
    ON ssf_events (next_attempt_at)
 WHERE delivered_at IS NULL;

COMMENT ON COLUMN ssf_events.token IS
    'A Security Event Token (RFC 8417), signed with the OIDC signing key so a '
    'receiver verifies it against the JWKS it already fetches. No new key '
    'distribution, and rotation is the one that already exists.';

-- Where the transmitter has read up to in the journal.
--
-- Events are emitted by following the hash-chained journal rather than by
-- calling a notifier from each handler. The first version did the latter and
-- was wrong in a way worth recording: the emission sat in the HTTP layer, so
-- `cardinal user disable` on the server changed the directory and told nobody.
-- Two paths, one of them unchecked, which is the shape this project keeps
-- finding.
--
-- The journal already records every one of these acts, whatever performed
-- them, and it is the one place they all pass through. One watermark shared by
-- every server: whoever takes the row advances it, the others find nothing to
-- do, and a restart resumes rather than skipping whatever happened while the
-- process was down.
CREATE TABLE ssf_watermark (
    id  boolean PRIMARY KEY DEFAULT true CHECK (id),
    seq bigint NOT NULL DEFAULT 0
);

-- Starts at the current end of the journal, not at zero.
--
-- A deployment that has been running for a year would otherwise transmit its
-- entire history to the first receiver anybody configures — thousands of
-- revocations, every one of them stale, and an application acting on all of
-- them.
INSERT INTO ssf_watermark (id, seq)
SELECT true, coalesce(max(seq), 0) FROM events
ON CONFLICT (id) DO NOTHING;
