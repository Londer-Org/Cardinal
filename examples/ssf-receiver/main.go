// Command ssf-receiver accepts Security Event Tokens and verifies them.
//
// The point of it is that it is not Cardinal. Everything else in the
// end-to-end stack proves Cardinal agrees with itself; this fetches the JWKS
// like any receiver would, verifies signatures against it, and records what
// arrived — so "a revocation reaches the applications" is a claim something
// external checked rather than one this project asserts about its own output.
//
// Deliberately small and deliberately strict. It rejects a token whose
// signature does not verify, whose issuer is not the one it discovered, or
// whose audience is not its own client id — because a receiver that accepts
// those is one that proves nothing about the transmitter.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type received struct {
	Type      string `json:"type"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Audience  string `json:"audience"`
	Timestamp int64  `json:"timestamp"`
	JTI       string `json:"jti"`
}

type receiver struct {
	issuer   string
	jwksURI  string
	audience string

	mu       sync.Mutex
	events   []received
	rejected []string
}

func main() {
	r := &receiver{
		issuer:   os.Getenv("CARDINAL_ISSUER"),
		jwksURI:  os.Getenv("CARDINAL_JWKS"),
		audience: os.Getenv("CARDINAL_CLIENT_ID"),
	}
	if r.issuer == "" || r.jwksURI == "" {
		log.Fatal("CARDINAL_ISSUER and CARDINAL_JWKS are required")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /events", r.accept)
	mux.HandleFunc("GET /received", r.list)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = "0.0.0.0:8000"
	}
	// The issuer comes from this container's own environment, not from a
	// request, so there is nothing here for a caller to inject.
	log.Printf("ssf-receiver listening on %s, issuer %s", addr, r.issuer) //nolint:gosec // G706: the value is configuration, not input
	server := &http.Server{
		Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

// accept verifies one pushed token.
//
// 202 on success, which is what RFC 8935 specifies. A rejection is 400 and is
// recorded too: a test asserting that a *bad* token is refused needs somewhere
// to look, and a receiver that silently drops them proves nothing either way.
func (r *receiver) accept(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 64<<10))
	if err != nil {
		r.reject(w, "unreadable body")
		return
	}

	keys, err := r.fetchKeys()
	if err != nil {
		// 500 rather than 400: the transmitter did nothing wrong, and a 4xx
		// would make it stop retrying something that would have worked.
		http.Error(w, "cannot fetch keys: "+err.Error(), http.StatusInternalServerError)
		return
	}

	parsed, err := jwt.ParseSigned(string(body), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		r.reject(w, "not a signed JWT: "+err.Error())
		return
	}

	var claims map[string]any
	if err := parsed.Claims(keys, &claims); err != nil {
		r.reject(w, "signature does not verify against the published JWKS: "+err.Error())
		return
	}

	issuer, _ := claims["iss"].(string) //nolint:errcheck // a missing claim is the check below
	if issuer != r.issuer {
		r.reject(w, fmt.Sprintf("issuer %q is not %q", issuer, r.issuer))
		return
	}
	audience, _ := claims["aud"].(string) //nolint:errcheck // as above
	if r.audience != "" && audience != r.audience {
		r.reject(w, fmt.Sprintf("audience %q is not this receiver", audience))
		return
	}

	events, ok := claims["events"].(map[string]any)
	if !ok || len(events) != 1 {
		r.reject(w, "a security event token carries exactly one event")
		return
	}

	for eventType, raw := range events {
		detail, _ := raw.(map[string]any) //nolint:errcheck // a non-object detail leaves the fields below empty, which the receiver records as-is
		entry := received{
			Type: eventType, Issuer: issuer, Audience: audience,
		}
		if jti, ok := claims["jti"].(string); ok {
			entry.JTI = jti
		}
		if ts, ok := detail["event_timestamp"].(float64); ok {
			entry.Timestamp = int64(ts)
		}
		if subject, ok := detail["subject"].(map[string]any); ok {
			entry.Subject, _ = subject["sub"].(string) //nolint:errcheck // absent means empty, which the test asserts on
		}

		r.mu.Lock()
		r.events = append(r.events, entry)
		r.mu.Unlock()
		log.Printf("accepted %s for %s", entry.Type, entry.Subject)
	}

	w.WriteHeader(http.StatusAccepted)
}

func (r *receiver) reject(w http.ResponseWriter, reason string) {
	r.mu.Lock()
	r.rejected = append(r.rejected, reason)
	r.mu.Unlock()
	log.Printf("rejected: %s", reason)
	http.Error(w, reason, http.StatusBadRequest)
}

func (r *receiver) list(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // header already written
		"events":   r.events,
		"rejected": r.rejected,
	})
}

// fetchKeys reads the transmitter's JWKS.
//
// Fetched per request rather than cached, which is wrong for production and
// right here: the whole point is to verify against what Cardinal publishes
// right now, and a cache would let a test pass against a key that had been
// rotated away.
func (r *receiver) fetchKeys() (*jose.JSONWebKeySet, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(r.jwksURI) //nolint:noctx // bounded by the client timeout
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // nothing actionable remains

	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}
	return &keys, nil
}
