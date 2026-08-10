-- Cardinal 0032: letting a receiver fetch events instead of being pushed them.
--
-- Push (RFC 8935) requires the receiver to run an HTTPS endpoint Cardinal can
-- reach. That is a reasonable thing to ask of a service in the same network and
-- an unreasonable one otherwise: a receiver behind NAT, on a laptop, or inside a
-- CI job has no such address, and neither does one whose operator will not open
-- an inbound path to a security-event handler. RFC 8936 is the other direction —
-- the receiver connects, asks what is waiting, and acknowledges what it took.
--
-- Nothing about the token changes. The same signed Security Event Token is
-- delivered either way, so a receiver that switches direction verifies exactly
-- what it verified before.

-- How this receiver is delivered to.
--
-- A column rather than a second table: a stream is delivered one way at a time,
-- and the specification models this as the stream's delivery configuration
-- rather than as two kinds of stream.
--
-- Defaulting to push keeps every existing stream doing what it does now.
ALTER TABLE ssf_streams
    ADD COLUMN delivery_method text NOT NULL DEFAULT 'push'
        CONSTRAINT ssf_streams_delivery_method_known
        CHECK (delivery_method IN ('push', 'poll'));

-- A poll stream has nowhere to be pushed to, and the endpoint column is NOT
-- NULL, so it holds the empty string. The constraint says which combinations
-- are meaningful: push needs somewhere to send, poll must not claim to have
-- one, because an endpoint that is recorded and never used is a fact that
-- quietly stops being true.
ALTER TABLE ssf_streams
    ADD CONSTRAINT ssf_streams_endpoint_matches_delivery
    CHECK (
        (delivery_method = 'push' AND endpoint <> '')
        OR
        (delivery_method = 'poll' AND endpoint = '')
    );

-- The https check predates this and would reject a poll stream's empty
-- endpoint, so it now applies only where there is an endpoint at all.
--
-- widens: ssf_streams_endpoint_is_https — every row the old check accepted, the
-- new one accepts; it adds the empty string and nothing else. A cleartext
-- endpoint is still refused, which is the rule that matters.
--
-- The empty string rather than NULL deliberately, and the reason is rollback.
-- A previous version scans this column into a plain Go string, in the query
-- that lists every enabled stream. Measured against pgx: scanning NULL into a
-- *string returns "cannot scan NULL into *string", and the empty string scans
-- clean. Because that error fails the whole query rather than one row, a single
-- poll stream would stop push delivery to all the others on a build that
-- predates this. The empty string is instead read as an endpoint that cannot be
-- posted to, which fails that one stream's deliveries and leaves the rest
-- alone.
ALTER TABLE ssf_streams DROP CONSTRAINT ssf_streams_endpoint_is_https;
ALTER TABLE ssf_streams
    ADD CONSTRAINT ssf_streams_endpoint_is_https
    CHECK (endpoint = '' OR endpoint LIKE 'https://%');

COMMENT ON COLUMN ssf_streams.delivery_method IS
    'push (RFC 8935) posts each event to endpoint; poll (RFC 8936) holds it '
    'until the receiver asks. Poll streams have no endpoint: the receiver '
    'connects to Cardinal.';

-- The token identifier, so a receiver can say which events it has taken.
--
-- RFC 8936 keys the response by jti and acknowledges by the same value, so it
-- has to be readable without parsing the token. It is already inside the
-- signed token — this is the same value lifted out, not a second identifier,
-- and the transmitter writes both from one place so they cannot disagree.
--
-- Nullable because rows queued before this migration have one inside their
-- token and nothing in the column. Those are push rows by definition, which
-- never look at it.
ALTER TABLE ssf_events ADD COLUMN jti uuid;

-- Poll delivery reads by stream, oldest first, and only what is outstanding.
-- The push index is on next_attempt_at, which answers a different question and
-- would mean a scan per poll.
CREATE INDEX ssf_events_unpolled_idx
    ON ssf_events (stream_id, created_at)
 WHERE delivered_at IS NULL;

COMMENT ON COLUMN ssf_events.jti IS
    'The jti of the signed token, lifted out so RFC 8936 poll responses can be '
    'keyed by it and acknowledged by it without parsing the token.';

-- The table comment predates poll delivery and said Cardinal pushes to these
-- receivers, full stop. Half of that is now wrong in the direction that
-- matters: somebody reading the schema to find out how events reach an
-- application would conclude there is only one way.
COMMENT ON TABLE ssf_streams IS
    'Receivers Cardinal sends security events to. push (RFC 8935) posts each '
    'event to the receiver''s endpoint; poll (RFC 8936) holds it until the '
    'receiver collects it with a credential of its own. Streams are configured '
    'by an administrator: stream management over the API is not implemented, '
    'and the SSF configuration document says so.';
