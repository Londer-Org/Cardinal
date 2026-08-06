package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"sort"
	"time"
)

// The relying party's interface.
//
// Deliberately looks nothing like Cardinal. The point of this example is to sit
// in a second browser tab beside the identity provider, and two tabs that share
// a visual language make it easy to lose track of which system is asking for
// what — which is the exact confusion phishing relies on. So: different colour,
// different type, its own name.
//
// It is also written to be read. Everything shown here arrived in an ID token
// this application verified itself, and the page says so, because "what does an
// application actually receive from Cardinal?" is the question this example
// exists to answer.

type viewData struct {
	AppName string

	SignedIn  bool
	Subject   string
	Name      string
	Username  string
	Email     string
	Groups    []string
	Refreshed int

	// AccessExpiresIn is how long the access token has left. Shown because a
	// short-lived token silently renewing behind the scenes is the part of OIDC
	// people find hardest to believe until they watch it happen.
	AccessExpiresIn string
	HasRefresh      bool

	ClaimsJSON string
	Issuer     string
}

func (c *client) view(r *http.Request) viewData {
	data := viewData{AppName: appName, Issuer: c.issuer}

	sess := c.session(r)
	if sess == nil {
		return data
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	data.SignedIn = true
	data.Subject = sess.Subject
	data.Refreshed = sess.Refreshed
	data.Name, _ = sess.Claims["name"].(string)
	data.Username, _ = sess.Claims["preferred_username"].(string)
	data.Email, _ = sess.Claims["email"].(string)

	if raw, ok := sess.Claims["groups"].([]any); ok {
		for _, g := range raw {
			if name, ok := g.(string); ok {
				data.Groups = append(data.Groups, name)
			}
		}
		sort.Strings(data.Groups)
	}

	if sess.Token != nil {
		data.HasRefresh = sess.Token.RefreshToken != ""
		if !sess.Token.Expiry.IsZero() {
			left := time.Until(sess.Token.Expiry).Round(time.Second)
			if left < 0 {
				data.AccessExpiresIn = "expired"
			} else {
				data.AccessExpiresIn = left.String()
			}
		}
	}

	if pretty, err := json.MarshalIndent(sess.Claims, "", "  "); err == nil {
		data.ClaimsJSON = string(pretty)
	}

	return data
}

func (c *client) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, c.view(r)); err != nil {
		// Nothing useful to do — the response is already partly written.
		return
	}
}

// handleSignOut ends the local session only.
//
// Deliberately not an RP-initiated logout at the provider: signing out of one
// application should not sign you out of the identity provider and every other
// application with it. Watching this tab return to signed-out while the
// Cardinal tab stays signed in is the clearest way to see what a session at
// each layer actually means.
func (c *client) handleSignOut(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		c.mu.Lock()
		delete(c.sessions, cookie.Value)
		c.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

const appName = "Meridian Analytics"

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ .AppName }}</title>
<style>
  :root {
    --bg: #fbfaf7; --fg: #1c1a17; --muted: #6b6459; --line: #e6e1d7;
    --card: #ffffff; --accent: #b45309; --accent-fg: #ffffff; --code: #f5f2ec;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #17150f; --fg: #f0ece4; --muted: #a09889; --line: #322d24;
      --card: #201d16; --accent: #d97706; --accent-fg: #17150f; --code: #12100b;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  .wrap { max-width: 44rem; margin: 0 auto; padding: 3rem 1.25rem 4rem; }
  header { display: flex; align-items: center; gap: .75rem; margin-bottom: .25rem; }
  .mark {
    width: 2rem; height: 2rem; border-radius: .5rem; background: var(--accent);
    color: var(--accent-fg); display: grid; place-items: center;
    font-weight: 700; font-size: .95rem; flex: none;
  }
  h1 { font-size: 1.35rem; margin: 0; letter-spacing: -.01em; }
  .sub { color: var(--muted); font-size: .875rem; margin: 0 0 2rem; }
  .card {
    background: var(--card); border: 1px solid var(--line);
    border-radius: .75rem; padding: 1.25rem; margin-bottom: 1rem;
  }
  h2 { font-size: .95rem; margin: 0 0 .75rem; }
  .btn {
    display: inline-block; background: var(--accent); color: var(--accent-fg);
    border: 0; border-radius: .5rem; padding: .6rem 1rem; font: inherit;
    font-weight: 500; cursor: pointer; text-decoration: none;
  }
  .btn.ghost { background: transparent; color: var(--muted); border: 1px solid var(--line); }
  .row { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
  dl { display: grid; grid-template-columns: 9rem 1fr; gap: .4rem 1rem; margin: 0; }
  dt { color: var(--muted); font-size: .875rem; }
  dd { margin: 0; font-size: .875rem; word-break: break-word; }
  .chip {
    display: inline-block; background: var(--code); border: 1px solid var(--line);
    border-radius: 999px; padding: .1rem .6rem; font-size: .8rem; margin: 0 .25rem .25rem 0;
  }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  pre {
    background: var(--code); border: 1px solid var(--line); border-radius: .5rem;
    padding: .9rem; overflow-x: auto; font-size: .8rem; margin: 0;
  }
  .note { color: var(--muted); font-size: .8rem; margin: .75rem 0 0; }
  summary { cursor: pointer; font-size: .875rem; color: var(--muted); }
  a { color: var(--accent); }
</style>
<body>
<div class="wrap">
  <header>
    <div class="mark">M</div>
    <h1>{{ .AppName }}</h1>
  </header>
  <p class="sub">
    A demonstration relying party. It knows nothing about Cardinal beyond its
    issuer URL, and verifies everything it is told.
  </p>

{{ if not .SignedIn }}
  <div class="card">
    <h2>Not signed in</h2>
    <p style="margin:0 0 1rem">
      This application has no accounts, no passwords and no user table. It asks
      Cardinal who you are and trusts the answer only because it can check the
      signature against published keys.
    </p>
    <a class="btn" href="/login">Sign in with Cardinal</a>
    <p class="note">
      Provider: <code>{{ .Issuer }}</code>
    </p>
  </div>

  <div class="card">
    <h2>What to watch</h2>
    <p class="note" style="margin-top:0">
      If you are already signed in to Cardinal in another tab, this will not ask
      you to authenticate again — that is single sign-on. If the application was
      registered with <code>-consent</code>, Cardinal will stop and ask before
      releasing anything.
    </p>
  </div>
{{ else }}
  <div class="card">
    <h2>Signed in</h2>
    <dl>
      <dt>Name</dt><dd>{{ if .Name }}{{ .Name }}{{ else }}<em>not provided</em>{{ end }}</dd>
      <dt>Username</dt><dd>{{ if .Username }}{{ .Username }}{{ else }}<em>not provided</em>{{ end }}</dd>
      <dt>Email</dt><dd>{{ if .Email }}{{ .Email }}{{ else }}<em>not provided</em>{{ end }}</dd>
      <dt>Subject</dt><dd><code>{{ .Subject }}</code></dd>
      <dt>Groups</dt>
      <dd>
        {{ if .Groups }}{{ range .Groups }}<span class="chip">{{ . }}</span>{{ end }}
        {{ else }}<em>none</em>{{ end }}
      </dd>
    </dl>
    <p class="note">
      The subject is an immutable UUID, not the username. Rename the account in
      Cardinal and this value does not change — which is why it, and never the
      login, is what an application should store.
    </p>
  </div>

  <div class="card">
    <h2>Tokens</h2>
    <dl>
      <dt>Access token</dt>
      <dd>{{ if .AccessExpiresIn }}expires in {{ .AccessExpiresIn }}{{ else }}no expiry reported{{ end }}</dd>
      <dt>Refresh token</dt>
      <dd>{{ if .HasRefresh }}held{{ else }}<em>none — offline_access was not granted</em>{{ end }}</dd>
      <dt>Refreshed</dt><dd>{{ .Refreshed }} time(s)</dd>
    </dl>
    <div class="row" style="margin-top:1rem">
      {{ if .HasRefresh }}
      <form method="post" action="/refresh"><button class="btn ghost">Refresh tokens</button></form>
      {{ end }}
      <a class="btn ghost" href="/signout">Sign out of {{ .AppName }}</a>
    </div>
    <p class="note">
      Refreshing rotates: Cardinal revokes the old refresh token as it issues
      the new one, so a stolen one stops working the moment the real client
      refreshes. Signing out here ends this application's session only — the
      Cardinal tab stays signed in, which is what makes the next application
      instant.
    </p>
  </div>

  <div class="card">
    <details>
      <summary>Raw ID token claims</summary>
      <pre style="margin-top:.75rem">{{ .ClaimsJSON }}</pre>
    </details>
    <p class="note">
      Signature, issuer, audience and nonce were all verified against
      <code>{{ .Issuer }}</code> before any of this was displayed.
    </p>
  </div>
{{ end }}
</div>
`))
