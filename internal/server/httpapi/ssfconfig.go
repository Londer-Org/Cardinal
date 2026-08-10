package httpapi

import (
	"net/http"
	"strings"

	"go.londer.be/cardinal/internal/server/ssf"
)

// handleSSFConfiguration describes this transmitter to a receiver.
//
// Served unauthenticated, like the OIDC discovery document beside it and for
// the same reason: a receiver reads it before it has any credential, and it
// says nothing a caller could not learn by trying. What it does say is which
// half of the framework is implemented — a receiver expecting to create its own
// stream over the API finds out here rather than from a 404 during a
// deprovisioning.
func (s *Server) handleSSFConfiguration(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.cfg.Server.PublicURL, "/")

	body, err := ssf.Configuration{
		Issuer: issuer,
		// The same JWKS that verifies ID tokens. A receiver already fetches it,
		// so security events need no key distribution of their own and rotate
		// with the keys that already rotate.
		JWKSURI:                  issuer + "/oidc/keys",
		DeliveryMethodsSupported: []string{ssf.DeliveryPush, ssf.DeliveryPoll},
		PollEndpoint:             issuer + "/ssf/poll",
		SpecVersion:              "1_0-ID2",
		Note: "Streams are configured by a Cardinal administrator with " +
			"`cardinal ssf stream add`, not by the receiver over this API: " +
			"stream management is not implemented. Both delivery methods are: " +
			"push posts each token to an endpoint you give, poll has you " +
			"collect them from poll_endpoint with an access token issued by " +
			"`cardinal ssf token <application>` and sent as a bearer token.",
	}.MarshalIndent()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not describe this transmitter")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body) //nolint:errcheck // the header is already written
	_ = r
}
