// Command oidc-client is a relying party for the end-to-end stack.
//
// It uses coreos/go-oidc rather than the same library Cardinal's provider is
// built on. Testing zitadel's server against zitadel's client would mostly
// prove the two agree with each other; go-oidc is an independent
// implementation and is what most Go services actually use, so satisfying it
// is evidence the provider is correct rather than merely self-consistent.
//
// It does full validation: discovery, JWKS fetch, signature, issuer, audience
// and nonce. Any of those failing is a real finding.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func main() {
	var (
		issuer      = env("OIDC_ISSUER", "http://id.localhost:8100")
		clientID    = os.Getenv("OIDC_CLIENT_ID")
		redirectURL = env("OIDC_REDIRECT_URL", "http://client.localhost:8100/callback")
		listen      = env("LISTEN", "0.0.0.0:8000")
	)
	if clientID == "" {
		log.Fatal("OIDC_CLIENT_ID is required")
	}

	ctx := context.Background()

	// Discovery is retried: in a compose stack the client frequently starts
	// before the provider is serving, and failing permanently on the first
	// attempt would make the stack's startup order load-bearing.
	provider, err := discoverWithRetry(ctx, issuer, 60*time.Second)
	if err != nil {
		log.Fatalf("discovery failed: %v", err)
	}
	log.Printf("discovered issuer %s", issuer)

	app := &client{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		oauth: &oauth2.Config{
			ClientID:    clientID,
			RedirectURL: redirectURL,
			Endpoint:    provider.Endpoint(),
			// offline_access is what asks for a refresh token; without it the
			// provider correctly issues none.
			Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups", "offline_access"},
		},
		pending:  map[string]pendingLogin{},
		sessions: map[string]*session{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.handleHome)
	mux.HandleFunc("GET /login", app.handleLogin)
	mux.HandleFunc("GET /callback", app.handleCallback)
	mux.HandleFunc("POST /refresh", app.handleRefresh)
	mux.HandleFunc("GET /whoami.json", app.handleWhoami)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	log.Printf("oidc-client listening on %s", listen)
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}

type client struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config

	mu sync.Mutex
	// pending holds in-flight logins by state. A real application would use a
	// signed cookie; a map is honest for a test fixture and makes the PKCE and
	// nonce handling visible rather than hidden in a framework.
	pending  map[string]pendingLogin
	sessions map[string]*session
}

type pendingLogin struct {
	verifier string
	nonce    string
	created  time.Time
}

type session struct {
	Subject   string         `json:"sub"`
	Claims    map[string]any `json:"claims"`
	Token     *oauth2.Token  `json:"-"`
	Refreshed int            `json:"refreshed"`
}

func (c *client) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := random()
	nonce := random()
	verifier := oauth2.GenerateVerifier()

	c.mu.Lock()
	c.pending[state] = pendingLogin{verifier: verifier, nonce: nonce, created: time.Now()}
	c.mu.Unlock()

	// S256 challenge and a nonce, both checked on the way back. go-oidc
	// verifies the nonce against the ID token, so a provider that dropped it
	// would fail here rather than silently.
	url := c.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

func (c *client) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")

	c.mu.Lock()
	pending, ok := c.pending[state]
	delete(c.pending, state)
	c.mu.Unlock()

	if !ok {
		// An unrecognised state means CSRF, or a stale tab. Either way the
		// response cannot be trusted.
		http.Error(w, "unknown or reused state", http.StatusBadRequest)
		return
	}

	token, err := c.oauth.Exchange(ctx, r.URL.Query().Get("code"),
		oauth2.VerifierOption(pending.verifier))
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in the token response", http.StatusBadGateway)
		return
	}

	// The real check. Verifies the signature against the provider's JWKS, the
	// issuer, the audience, and expiry.
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "id_token verification failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if idToken.Nonce != pending.nonce {
		// Replay protection: a token minted for a different authorization
		// would otherwise be accepted here.
		http.Error(w, "nonce mismatch", http.StatusBadGateway)
		return
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "could not read claims: "+err.Error(), http.StatusBadGateway)
		return
	}

	sid := random()
	c.mu.Lock()
	c.sessions[sid] = &session{Subject: idToken.Subject, Claims: claims, Token: token}
	c.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: "rp_session", Value: sid, Path: "/", HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleRefresh exercises refresh-token rotation.
//
// Cardinal revokes the old refresh token as it issues a new one, so calling
// this twice with the original token must fail the second time. That is the
// property this endpoint exists to make testable.
func (c *client) handleRefresh(w http.ResponseWriter, r *http.Request) {
	sess := c.session(r)
	if sess == nil {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	if sess.Token.RefreshToken == "" {
		http.Error(w, "no refresh token — was offline_access granted?", http.StatusBadRequest)
		return
	}

	previous := sess.Token.RefreshToken

	// The expiry is forced into the past so a refresh actually happens.
	//
	// oauth2.TokenSource only contacts the server when the access token has
	// expired, so calling it with a fresh token returns the cached one and
	// silently does nothing — which looked exactly like "rotation is broken"
	// until the token count in the database gave it away.
	stale := *sess.Token
	stale.Expiry = time.Now().Add(-time.Minute)

	refreshed, err := c.oauth.TokenSource(r.Context(), &stale).Token()
	if err != nil {
		http.Error(w, "refresh failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	c.mu.Lock()
	sess.Token = refreshed
	sess.Refreshed++
	c.mu.Unlock()

	writeJSON(w, map[string]any{
		"refreshed":      sess.Refreshed,
		"rotated":        refreshed.RefreshToken != previous,
		"newAccessToken": refreshed.AccessToken != "",
	})
}

func (c *client) handleWhoami(w http.ResponseWriter, r *http.Request) {
	sess := c.session(r)
	if sess == nil {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{
		"sub":       sess.Subject,
		"claims":    sess.Claims,
		"refreshed": sess.Refreshed,
	})
}

func (c *client) handleHome(w http.ResponseWriter, r *http.Request) {
	sess := c.session(r)
	if sess == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><meta charset=utf-8><title>Relying party</title>
<body style="font:15px/1.6 system-ui;max-width:36rem;margin:4rem auto">
<h1>Relying party</h1>
<p>This application knows nothing about Cardinal beyond its issuer URL.</p>
<p><a href="/login">Sign in with Cardinal</a></p>`)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homePage.Execute(w, sess)
}

func (c *client) session(r *http.Request) *session {
	cookie, err := r.Cookie("rp_session")
	if err != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[cookie.Value]
}

var homePage = template.Must(template.New("home").Funcs(template.FuncMap{
	"json": func(v any) string {
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	},
}).Parse(`<!doctype html><meta charset=utf-8><title>Relying party</title>
<body style="font:15px/1.6 system-ui;max-width:40rem;margin:4rem auto">
<h1>Signed in</h1>
<p>The ID token's signature, issuer, audience and nonce were all verified
against Cardinal's published metadata.</p>
<h2>Claims</h2>
<pre style="background:#f6f6f6;padding:1rem;overflow:auto">{{ json .Claims }}</pre>
<form method="post" action="/refresh"><button>Refresh tokens</button></form>
<p>Refreshed {{ .Refreshed }} time(s).</p>`))

// discoverWithRetry polls until the provider is serving.
func discoverWithRetry(ctx context.Context, issuer string, limit time.Duration) (*oidc.Provider, error) {
	deadline := time.Now().Add(limit)
	var lastErr error

	for attempt := 1; time.Now().Before(deadline); attempt++ {
		provider, err := oidc.NewProvider(ctx, issuer)
		if err == nil {
			return provider, nil
		}
		lastErr = err

		// Say something. A container that sits silently for a minute and then
		// exits gives no clue whether it is waiting for a dependency or
		// pointed at the wrong URL entirely — which is exactly the mistake
		// this loop is most likely to be hiding.
		if attempt == 1 || attempt%5 == 0 {
			log.Printf("discovery of %s not ready (attempt %d): %v", issuer, attempt, err)
		}
		time.Sleep(time.Second)
	}
	return nil, lastErr
}

func random() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
