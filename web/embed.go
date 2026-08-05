// Package web embeds the built admin interface into the binary.
//
// This is what keeps Cardinal a single artifact: one binary, one database, no
// separate web server to deploy and no version skew between frontend and
// backend (ADR 0008).
package web

import (
	"embed"
	"errors"
	"io/fs"
)

// dist holds the Vite build output.
//
// The `all:` prefix includes files beginning with `_`, which Vite emits for
// some chunk names and which //go:embed would otherwise silently skip —
// producing a UI that half-loads with no obvious cause.
//
// The placeholder keeps this compiling before the frontend has ever been built,
// so `go build ./...` works on a fresh clone.
//
//go:embed all:dist
var dist embed.FS

// ErrNoUI means the frontend was not built into this binary.
var ErrNoUI = errors.New("web: no admin UI embedded — run `make ui` before building")

// Assets returns the built UI rooted at dist/.
func Assets() (fs.FS, error) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, ErrNoUI
	}
	// A dist directory containing only the placeholder is not a UI. Detecting
	// that here means the server logs a clear reason rather than serving 404s.
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, ErrNoUI
	}
	return sub, nil
}
