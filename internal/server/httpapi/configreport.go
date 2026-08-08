package httpapi

import "net/http"

// The running configuration, read-only.
//
// Deliberately not an editor. Most of cardinal.toml cannot move into the
// database — the DSN is what reads it, the listen address is needed to bind,
// and the three encryption keys decrypt what is stored there — and of the rest,
// changing `rp_id` stops every registered passkey working. Those should be
// hard, and a form is not hard.
//
// What was missing was the ability to see it. Two settings were parsed,
// validated and read by nothing, and it took an audit to notice rather than a
// page anybody could open.
func (s *Server) handleConfigReport(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": s.cfg.Report(),
	})
}
