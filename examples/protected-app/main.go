// Command protected-app is a minimal service sitting behind Cardinal.
//
// Deliberately boring. This is what someone copies when integrating, so
// anything clever here would get cargo-culted into real applications. Its
// entire job is to prove that identity headers arrive.
//
// The security model is worth stating, because it is the part people get
// wrong: this service performs NO authentication of its own. It trusts the
// X-Auth-Request-* headers completely, which is only safe because it is
// unreachable except through the proxy. If it were exposed directly, anyone
// could set those headers and become anyone.
//
// That is a network property, not a code property. Nothing in this file can
// enforce it.
package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
)

type identity struct {
	UserID      string   `json:"userId"`
	Login       string   `json:"login"`
	Name        string   `json:"name"`
	Groups      []string `json:"groups"`
	AuthMethod  string   `json:"authMethod"`
	DeviceBound bool     `json:"deviceBound"`

	// GroupIDs are the same memberships by immutable identifier.
	//
	// What an application deciding what somebody may do should key on. Group
	// names are mutable attributes by design (ADR 0002), so a permission model
	// written against the string "aura-admins" repeats LDAP's mistake one layer
	// out. Names are for showing a person.
	GroupIDs []string `json:"groupIds"`

	// Policy names the rule that admitted this request. Logging it lets an
	// application's own logs be correlated with Cardinal's decision log, which
	// is the difference between "access denied" and "denied by
	// ssh-requires-device-bound at 14:32".
	Policy string `json:"policy"`
}

func identityFrom(r *http.Request) identity {
	groups := r.Header.Get("X-Auth-Request-Groups")
	groupIDs := r.Header.Get("X-Auth-Request-Group-Ids")

	id := identity{
		UserID:      r.Header.Get("X-Auth-Request-User"),
		Login:       r.Header.Get("X-Auth-Request-Preferred-Username"),
		Name:        r.Header.Get("X-Auth-Request-Name"),
		AuthMethod:  r.Header.Get("X-Auth-Request-Auth-Method"),
		DeviceBound: r.Header.Get("X-Auth-Request-Device-Bound") == "true",
		Policy:      r.Header.Get("X-Cardinal-Policy"),
	}
	if groups != "" {
		id.Groups = strings.Split(groups, ",")
	}
	if groupIDs != "" {
		id.GroupIDs = strings.Split(groupIDs, ",")
	}
	return id
}

func main() {
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = "0.0.0.0:8000"
	}

	mux := http.NewServeMux()

	// JSON, for the end-to-end test to assert against.
	mux.HandleFunc("GET /whoami.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(identityFrom(r)) //nolint:errcheck // the header is already written, so the status cannot be changed
	})

	// A liveness endpoint that must NOT be behind the auth middleware, so the
	// stack can tell "the app is down" apart from "the app refused you".
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok") //nolint:errcheck // the header is already written, so the status cannot be changed
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		id := identityFrom(r)

		// An empty user ID means the request did not come through the proxy.
		// Saying so plainly beats rendering a page with blank fields, which is
		// how people end up shipping an app that "worked in testing".
		if id.UserID == "" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "No identity headers. This service must only be "+ //nolint:errcheck // the header is already written, so the status cannot be changed
				"reachable through the authenticating proxy.")
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := page.Execute(w, id); err != nil {
			log.Printf("rendering: %v", err)
		}
	})

	log.Printf("protected-app listening on %s", addr) //nolint:gosec // addr comes from this process's own flag, not from a request
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * 1e9}
	log.Fatal(server.ListenAndServe())
}

var page = template.Must(template.New("page").Parse(`<!doctype html>
<meta charset="utf-8">
<title>Protected app</title>
<style>
  body { font: 15px/1.6 system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem; }
  dt { font-weight: 600; margin-top: .75rem; }
  dd { margin: 0; font-family: ui-monospace, monospace; }
  .note { color: #666; font-size: .875rem; margin-top: 2rem; }
</style>
<h1>You are through</h1>
<p>This service did no authentication. Cardinal decided, Traefik enforced, and
these headers arrived.</p>
<dl>
  <dt>User ID</dt><dd>{{ .UserID }}</dd>
  <dt>Login</dt><dd>{{ .Login }}</dd>
  <dt>Name</dt><dd>{{ .Name }}</dd>
  <dt>Groups</dt><dd>{{ if .Groups }}{{ range .Groups }}{{ . }} {{ end }}{{ else }}(none){{ end }}</dd>
  <dt>Authenticated with</dt><dd>{{ .AuthMethod }}</dd>
  <dt>Device-bound</dt><dd>{{ .DeviceBound }}</dd>
  <dt>Admitted by policy</dt><dd>{{ .Policy }}</dd>
</dl>
<p class="note">If you can reach this page without going through the proxy,
the deployment is broken: this service trusts those headers unconditionally.</p>
`))
