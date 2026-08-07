package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/store"
	"golang.org/x/crypto/ssh"
)

// How a host authenticates after enrolling.
//
// Not a bearer token. A machine holding a long-lived shared secret is the thing
// every agent-based system gets wrong: the secret sits in a file on a box an
// attacker may already have, and stealing it is indistinguishable from using
// it. The host has a keypair it generated itself, so it proves possession
// instead — Cardinal holds only the public half and has nothing to leak.
//
// The signed string is deliberately boring:
//
//	cardinal-host-v1\n<method>\n<path>\n<unix seconds>\n<fingerprint>
//
// Method and path are in it so a signature captured from one request cannot
// authorise a different one. The timestamp bounds replay. The fingerprint binds
// the signature to the key claiming to have made it, so a signature cannot be
// presented alongside somebody else's identity.

const (
	hostAuthScheme  = "Cardinal-Host"
	hostAuthVersion = "cardinal-host-v1"

	// hostAuthSkew bounds replay. Generous enough for a machine whose clock NTP
	// has not caught up with, tight enough that a captured Authorization header
	// is worth little — and the threat model already assumes working NTP,
	// because short-lived certificates depend on it too.
	hostAuthSkew = 60 * time.Second
)

type ctxHostKey int

const ctxHost ctxHostKey = 0

// HostFrom returns the authenticated host, if the request came from one.
func HostFrom(ctx context.Context) (*store.HostCredential, bool) {
	h, ok := ctx.Value(ctxHost).(*store.HostCredential)
	return h, ok
}

// signingString is what a host signs and what Cardinal reconstructs.
//
// Rebuilt from the request rather than taken from it, so the two can only agree
// when the request really is the one that was signed.
func signingString(method, path, timestamp, fingerprint string) []byte {
	return []byte(strings.Join([]string{
		hostAuthVersion, method, path, timestamp, fingerprint,
	}, "\n"))
}

// requireHost rejects anything not signed by an enrolled host.
//
// Deliberately separate from requireAuth rather than folded into it. A host is
// not a person, has no session, and must never reach an endpoint written with a
// person in mind — keeping the two authentications apart means that confusion
// cannot happen by forgetting a check.
func (s *Server) requireHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred, err := s.authenticateHost(r)
		if err != nil {
			// One message for every failure. Telling a caller whether the
			// fingerprint was known, the timestamp stale or the signature wrong
			// would help someone enumerate enrolled hosts.
			s.log.InfoContext(r.Context(), "host authentication failed", "error", err)
			writeError(w, http.StatusUnauthorized, "host authentication failed")
			return
		}

		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), ctxHost, cred)))
	})
}

func (s *Server) authenticateHost(r *http.Request) (*store.HostCredential, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, hostAuthScheme+" ") {
		return nil, errors.New("no host signature")
	}

	// <fingerprint>:<unix seconds>:<base64 signature>
	//
	// Split from the right, because the fingerprint contains a colon of its own:
	// ssh.FingerprintSHA256 returns "SHA256:<base64>". Splitting left-to-right
	// finds four fields in a perfectly well-formed header and rejects every
	// legitimate request — which looks exactly like an authentication failure
	// and is not one. Neither of the two right-hand fields can contain a colon:
	// one is decimal digits, the other standard base64.
	rest := strings.TrimPrefix(header, hostAuthScheme+" ")

	signatureAt := strings.LastIndexByte(rest, ':')
	if signatureAt < 0 {
		return nil, errors.New("malformed host signature")
	}
	timestampAt := strings.LastIndexByte(rest[:signatureAt], ':')
	if timestampAt < 0 {
		return nil, errors.New("malformed host signature")
	}

	fingerprint := rest[:timestampAt]
	timestamp := rest[timestampAt+1 : signatureAt]
	encoded := rest[signatureAt+1:]
	if fingerprint == "" || timestamp == "" || encoded == "" {
		return nil, errors.New("malformed host signature")
	}

	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return nil, errors.New("malformed timestamp")
	}
	// Both directions. A clock ahead of ours is as much of a problem as one
	// behind, and accepting the future would let a captured header be held
	// until it became valid.
	if skew := time.Since(time.Unix(seconds, 0)); skew > hostAuthSkew || skew < -hostAuthSkew {
		return nil, fmt.Errorf("timestamp is %s out", skew)
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("signature is not base64")
	}

	var signature ssh.Signature
	if err := ssh.Unmarshal(raw, &signature); err != nil {
		return nil, errors.New("signature is not an SSH signature")
	}

	cred, err := s.store.HostByCredential(r.Context(), fingerprint)
	if err != nil {
		return nil, err
	}

	// The path signed is the one being served. r.URL.Path is already the
	// decoded, cleaned path the router matched, so a request cannot present a
	// signature over one path and be routed to another.
	if err := cred.PublicKey.Verify(
		signingString(r.Method, r.URL.Path, timestamp, fingerprint), &signature,
	); err != nil {
		return nil, errors.New("signature does not verify")
	}

	return cred, nil
}
