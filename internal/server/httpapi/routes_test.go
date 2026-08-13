package httpapi

import (
	"log/slog"
	"testing"

	"go.londer.be/cardinal/internal/config"
)

// TestTheRoutesRegisterWithoutConflicting.
//
// net/http panics when two patterns overlap, and Handler is only called once,
// at start-up — so a duplicate registration is a server that will not boot, and
// nothing before this test noticed until a container crash-looped.
//
// That is exactly how it was found: `POST /api/directory/groups` already
// existed when a second one was added from a table of types, and the whole
// end-to-end stack had to be built and started to learn it. This costs
// milliseconds and says which two patterns.
//
// It needs no database. Handler wires handlers up; it does not call them.
func TestTheRoutesRegisterWithoutConflicting(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("registering the routes panicked, so the server would not "+
				"start: %v", r)
		}
	}()

	server := &Server{
		cfg: &config.Config{},
		log: slog.New(slog.DiscardHandler),
	}
	if server.Handler() == nil {
		t.Fatal("no handler")
	}
}
