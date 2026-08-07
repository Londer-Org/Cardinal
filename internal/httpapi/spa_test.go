package httpapi

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// TestDeepLinksSurviveANameWithADot.
//
// The single-page app owns every path that is not an API route or a real file,
// so a hard refresh or a pasted link has to reach index.html and let the client
// router decide. Getting that wrong is invisible in normal use: navigating
// inside the app never touches the server, so the page works right up until
// somebody reloads it or shares the URL.
//
// The rule used to be "a path containing a dot is a missing asset", which 404'd
// every entity whose name has one. That is not an edge case — a host is
// routinely web-01.prod or db.example.com, and dots are legal in logins and
// group names too (`namePattern` in internal/directory). The inventory page
// worked; every link out of it broke on reload.
//
// It still has to 404 a genuinely missing asset. A stale bundle requesting a
// chunk that no longer exists must not receive index.html, or the browser tries
// to parse HTML as JavaScript and the user gets a blank page and a syntax error
// rather than a clear failure.
func TestDeepLinksSurviveANameWithADot(t *testing.T) {
	ui := fstest.MapFS{
		"index.html":             {Data: []byte("<!doctype html><title>app</title>")},
		"favicon.svg":            {Data: []byte("<svg/>")},
		"assets/index-abc123.js": {Data: []byte("console.log(1)")},
	}

	server := &Server{ui: fs.FS(ui)}
	handler := server.spaHandler()

	for _, tc := range []struct {
		name string
		path string
		want int
		body string
	}{
		{"the app itself", "/", http.StatusOK, "<!doctype html>"},
		{"a client route", "/directory/hosts", http.StatusOK, "<!doctype html>"},
		{
			"a host with a fully-qualified name",
			"/directory/hosts/web-01.prod", http.StatusOK, "<!doctype html>",
		},
		{
			"a host with a longer domain",
			"/directory/hosts/db.example.com", http.StatusOK, "<!doctype html>",
		},
		{
			"a login with a dot, which namePattern permits",
			"/directory/people/first.last", http.StatusOK, "<!doctype html>",
		},
		{"a real asset", "/assets/index-abc123.js", http.StatusOK, "console.log"},
		{"the favicon", "/favicon.svg", http.StatusOK, "<svg/>"},
		{
			"a chunk from a stale bundle, which must not render the app",
			"/assets/index-oldhash.js", http.StatusNotFound, "",
		},
		{"an API route that does not exist", "/api/nope", http.StatusNotFound, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder,
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil))

			if recorder.Code != tc.want {
				t.Fatalf("%s returned %d, want %d", tc.path, recorder.Code, tc.want)
			}
			if tc.body != "" && !strings.Contains(recorder.Body.String(), tc.body) {
				t.Fatalf("%s served %q, expected it to contain %q",
					tc.path, recorder.Body.String(), tc.body)
			}
		})
	}
}
