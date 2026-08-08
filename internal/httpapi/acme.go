package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/acme"
	"go.londer.be/cardinal/internal/store"
)

// ACME, RFC 8555.
//
// Every endpoint below is a POST whose body is a JWS, including the ones that
// read — ACME has no authenticated GET, so a client "gets" by posting an empty
// payload (§6.3). That looks wrong and is the specification.
//
// Two things about this server are unusual and both come from the same fact:
// the client is a machine Cardinal already knows.
//
//   - Authorizations are born valid. A challenge exists to prove control of a
//     name, and the host proved which host it is when it enrolled.
//   - The names on the certificate come from the directory, never from the CSR.
//     A CSR is a request; entitlement is a separate question with a separate
//     answer.

// DefaultLeafValidity is how long an issued certificate lasts.
//
// Ninety days is the public-CA convention and is far too long here. Cardinal
// issues to machines running an agent that renews automatically, so the only
// argument for a long life is tolerating an outage — and thirty days of outage
// tolerance with renewal at a third of that is already more than any other
// credential in this system gets.
const DefaultLeafValidity = 30 * 24 * time.Hour

// acmeProblem is RFC 7807, as ACME uses it.
type acmeProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (s *Server) acmeError(w http.ResponseWriter, r *http.Request, status int, kind, detail string) {
	// A fresh nonce on every response, including errors. A client that got an
	// error and no nonce has to make an extra round trip before it can retry,
	// and §6.5 requires one anyway.
	s.attachNonce(r.Context(), w)

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(acmeProblem{
		Type:   "urn:ietf:params:acme:error:" + kind,
		Detail: detail,
		Status: status,
	})
}

func (s *Server) attachNonce(ctx context.Context, w http.ResponseWriter) {
	nonce, err := s.store.NewACMENonce(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "acme: could not issue a nonce", "error", err)
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	// Without this a browser-based client cannot read the header, and the
	// specification asks for it explicitly (§6.4.1).
	w.Header().Set("Cache-Control", "no-store")
}

// acmeURL builds an absolute URL for the directory document and Location
// headers.
//
// From configuration rather than from the request. Deriving it from the Host
// header would let a client that reached Cardinal through any name at all
// receive a directory pointing back at that name — and the `url` check in every
// signed request compares against this, so a request signed for one spelling
// would fail against another.
func (s *Server) acmeURL(path string) string {
	base := s.cfg.X509.ACMEBaseURL(s.cfg.Server.PublicURL)
	return strings.TrimRight(base, "/") + "/acme" + path
}

// handleACMEDirectory is the one endpoint a client is configured with.
func (s *Server) handleACMEDirectory(w http.ResponseWriter, r *http.Request) {
	if s.x509CA == nil {
		writeError(w, http.StatusNotImplemented,
			"this deployment does not issue X.509 certificates")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"newNonce":   s.acmeURL("/new-nonce"),
		"newAccount": s.acmeURL("/new-account"),
		"newOrder":   s.acmeURL("/new-order"),
		"revokeCert": s.acmeURL("/revoke-cert"),
		"keyChange":  s.acmeURL("/key-change"),
		"meta": map[string]any{
			// Required, and it is how a client discovers it needs a credential
			// before it can do anything. A client that omits the binding is
			// told so by its own library rather than by a refusal here.
			"externalAccountRequired": true,
			"website":                 strings.TrimRight(s.cfg.Server.PublicURL, "/"),
		},
	})
	_ = r
}

func (s *Server) handleACMENewNonce(w http.ResponseWriter, r *http.Request) {
	s.attachNonce(r.Context(), w)
	// HEAD gets 200 and GET gets 204, which is the wrong way round until you
	// read §7.2: a GET here is the odd one out and the specification says so.
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// verified is a request whose signature has been checked.
type verified struct {
	header  *acme.Header
	jws     *acme.JWS
	payload []byte
	account *store.ACMEAccount
}

// verify does everything every authenticated ACME request needs.
//
// The order matters and is the specification's: parse, check the nonce, check
// the URL, then verify the signature. Checking the signature first would let an
// attacker use this endpoint as an oracle for whether a nonce was still live.
func (s *Server) verify(w http.ResponseWriter, r *http.Request, needAccount bool) (*verified, bool) {
	ctx := r.Context()

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "malformed", "could not read the request")
		return nil, false
	}

	header, jws, err := acme.Decode(body)
	if err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "malformed", err.Error())
		return nil, false
	}

	if err := s.store.ConsumeACMENonce(ctx, header.Nonce); err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "badNonce",
			"the nonce was not issued by this server, or has already been used")
		return nil, false
	}

	// The signed `url` must be the one being served. Without it a JWS captured
	// from one endpoint could be replayed at another that happens to accept the
	// same payload shape.
	if header.URL != s.acmeURL(strings.TrimPrefix(r.URL.Path, "/acme")) {
		s.acmeError(w, r, http.StatusBadRequest, "unauthorized",
			"the signed url does not match this endpoint")
		return nil, false
	}

	out := &verified{header: header, jws: jws}

	if needAccount {
		if header.KID == "" {
			s.acmeError(w, r, http.StatusBadRequest, "malformed",
				"this request must be signed by an account key")
			return nil, false
		}
		account, ok := s.accountFromKID(w, r, header.KID)
		if !ok {
			return nil, false
		}
		out.account = account

		var jwk acme.JWK
		if err := json.Unmarshal(account.PublicJWK, &jwk); err != nil {
			s.acmeError(w, r, http.StatusInternalServerError, "serverInternal",
				"the stored account key is unreadable")
			return nil, false
		}
		key, err := jwk.PublicKey()
		if err != nil {
			s.acmeError(w, r, http.StatusInternalServerError, "serverInternal",
				"the stored account key is unusable")
			return nil, false
		}
		if err := acme.Verify(header, jws, key); err != nil {
			s.acmeError(w, r, http.StatusUnauthorized, "unauthorized",
				"the request signature is not valid")
			return nil, false
		}
	}

	if out.payload, err = jws.Body(); err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "malformed",
			"the payload is not base64url")
		return nil, false
	}
	return out, true
}

func (s *Server) accountFromKID(w http.ResponseWriter, r *http.Request, kid string) (*store.ACMEAccount, bool) {
	parsed, err := url.Parse(kid)
	if err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "malformed", "kid is not a URL")
		return nil, false
	}
	id, err := uuid.Parse(strings.TrimPrefix(parsed.Path, "/acme/account/"))
	if err != nil {
		s.acmeError(w, r, http.StatusUnauthorized, "accountDoesNotExist",
			"no such account")
		return nil, false
	}

	account, err := s.store.ACMEAccountByID(r.Context(), id)
	if err != nil || account.Deactivated {
		s.acmeError(w, r, http.StatusUnauthorized, "accountDoesNotExist",
			"no such account")
		return nil, false
	}
	return account, true
}

type newAccountRequest struct {
	Contact                []string        `json:"contact"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
}

// handleACMENewAccount binds a client key to a host.
//
// The one endpoint where the request carries its own key in `jwk` rather than
// naming an account — there is no account yet. Which is exactly why the binding
// is required: without it this would create an account belonging to nobody, and
// every later request would be authenticated as that nobody.
func (s *Server) handleACMENewAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, ok := s.verify(w, r, false)
	if !ok {
		return
	}
	if len(req.header.JWK) == 0 {
		s.acmeError(w, r, http.StatusBadRequest, "malformed",
			"a new account must carry its key in jwk")
		return
	}

	var jwk acme.JWK
	if err := json.Unmarshal(req.header.JWK, &jwk); err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "malformed", "jwk is not a JWK")
		return
	}
	key, err := jwk.PublicKey()
	if err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "badPublicKey", err.Error())
		return
	}
	if err := acme.Verify(req.header, req.jws, key); err != nil {
		s.acmeError(w, r, http.StatusUnauthorized, "unauthorized",
			"the request is not signed by the key it carries")
		return
	}

	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "badPublicKey", err.Error())
		return
	}

	var body newAccountRequest
	if len(req.payload) > 0 {
		if err := json.Unmarshal(req.payload, &body); err != nil {
			s.acmeError(w, r, http.StatusBadRequest, "malformed",
				"the payload is not JSON")
			return
		}
	}

	if len(body.ExternalAccountBinding) == 0 {
		s.acmeError(w, r, http.StatusBadRequest, "externalAccountRequired",
			"this server issues only to enrolled hosts — run "+
				"`cardinal host acme-credentials <name>` and configure the "+
				"external account binding it prints")
		return
	}

	subjectID, boundKey, err := s.bindAccount(ctx, body.ExternalAccountBinding)
	if err != nil {
		s.acmeError(w, r, http.StatusUnauthorized, "unauthorized",
			"the external account binding cannot be used")
		return
	}

	// The binding's payload is the account key it vouches for. If it named a
	// different key, somebody is replaying a binding captured from elsewhere to
	// attach their own key to a host they do not have.
	var bound acme.JWK
	if err := json.Unmarshal(boundKey, &bound); err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "malformed",
			"the binding does not carry a key")
		return
	}
	boundThumb, err := bound.Thumbprint()
	if err != nil || boundThumb != thumbprint {
		s.acmeError(w, r, http.StatusUnauthorized, "unauthorized",
			"the external account binding is for a different key")
		return
	}

	account, err := s.store.CreateACMEAccount(ctx, subjectID,
		thumbprint, req.header.JWK, body.Contact)
	if err != nil {
		s.log.ErrorContext(ctx, "acme: creating an account failed", "error", err)
		s.acmeError(w, r, http.StatusInternalServerError, "serverInternal",
			"could not create the account")
		return
	}

	s.log.InfoContext(ctx, "acme account created",
		"account", account.ID, "subject", account.SubjectID)

	s.attachNonce(ctx, w)
	w.Header().Set("Location", s.acmeURL("/account/"+account.ID.String()))
	writeJSON(w, http.StatusCreated, map[string]any{
		"status":  "valid",
		"contact": account.Contact,
		"orders":  s.acmeURL("/account/" + account.ID.String() + "/orders"),
	})
}

type newOrderRequest struct {
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
}

// handleACMENewOrder accepts a request for names, and decides.
func (s *Server) handleACMENewOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, ok := s.verify(w, r, true)
	if !ok {
		return
	}

	var body newOrderRequest
	if err := json.Unmarshal(req.payload, &body); err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "malformed", "the payload is not JSON")
		return
	}
	if len(body.Identifiers) == 0 {
		s.acmeError(w, r, http.StatusBadRequest, "malformed", "an order must name identifiers")
		return
	}

	// What this subject is entitled to, from the directory. The request has no
	// say — a machine asking for payments.internal gets refused rather than
	// answered.
	entitled, err := s.store.HostPrincipals(ctx, req.account.SubjectID)
	if err != nil {
		s.acmeError(w, r, http.StatusForbidden, "unauthorized",
			"this account's subject has no names")
		return
	}

	wanted := make([]string, 0, len(body.Identifiers))
	for _, identifier := range body.Identifiers {
		if identifier.Type != "dns" {
			s.acmeError(w, r, http.StatusBadRequest, "unsupportedIdentifier",
				"only dns identifiers are supported")
			return
		}
		if !slices.Contains(entitled, identifier.Value) {
			// Named explicitly. This is not a secret — the client knows what it
			// asked for — and a vague refusal would send somebody looking at
			// their ACME client rather than at `cardinal host alias`.
			s.acmeError(w, r, http.StatusForbidden, "rejectedIdentifier",
				fmt.Sprintf("%s may not hold a certificate for %q; "+
					"grant it with `cardinal host alias add`",
					req.account.Subject, identifier.Value))
			return
		}
		wanted = append(wanted, identifier.Value)
	}

	order, err := s.store.CreateACMEOrder(ctx, req.account.ID, wanted)
	if err != nil {
		s.log.ErrorContext(ctx, "acme: creating an order failed", "error", err)
		s.acmeError(w, r, http.StatusInternalServerError, "serverInternal",
			"could not create the order")
		return
	}

	s.attachNonce(ctx, w)
	w.Header().Set("Location", s.acmeURL("/order/"+order.ID.String()))
	writeJSON(w, http.StatusCreated, s.orderJSON(order))
}

func (s *Server) orderJSON(order *store.ACMEOrder) map[string]any {
	identifiers := make([]map[string]string, 0, len(order.Identifiers))
	for _, value := range order.Identifiers {
		identifiers = append(identifiers, map[string]string{"type": "dns", "value": value})
	}
	authorizations := make([]string, 0, len(order.Authorizations))
	for _, a := range order.Authorizations {
		authorizations = append(authorizations, s.acmeURL("/authz/"+a.ID.String()))
	}

	out := map[string]any{
		"status":         order.Status,
		"expires":        order.ExpiresAt.UTC().Format(time.RFC3339),
		"identifiers":    identifiers,
		"authorizations": authorizations,
		"finalize":       s.acmeURL("/order/" + order.ID.String() + "/finalize"),
	}
	if order.Status == "valid" {
		out["certificate"] = s.acmeURL("/cert/" + order.ID.String())
	}
	return out
}

// handleACMEOrder is POST-as-GET for an order.
func (s *Server) handleACMEOrder(w http.ResponseWriter, r *http.Request) {
	req, ok := s.verify(w, r, true)
	if !ok {
		return
	}

	order, ok := s.orderForAccount(w, r, req.account)
	if !ok {
		return
	}

	s.attachNonce(r.Context(), w)
	writeJSON(w, http.StatusOK, s.orderJSON(order))
}

// handleACMEAuthorization is POST-as-GET for an authorization.
//
// Always valid, with no challenges. A client reading this learns there is
// nothing to do, which is the point — and an empty challenge array is what
// §7.1.4 says a valid authorization may carry.
func (s *Server) handleACMEAuthorization(w http.ResponseWriter, r *http.Request) {
	req, ok := s.verify(w, r, true)
	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.acmeError(w, r, http.StatusNotFound, "malformed", "no such authorization")
		return
	}

	authz, orderID, err := s.store.ACMEAuthorizationByID(r.Context(), id)
	if err != nil {
		s.acmeError(w, r, http.StatusNotFound, "malformed", "no such authorization")
		return
	}

	order, err := s.store.ACMEOrderByID(r.Context(), orderID)
	if err != nil || order.AccountID != req.account.ID {
		// Not found rather than forbidden: whether somebody else's
		// authorization exists is not this account's business.
		s.acmeError(w, r, http.StatusNotFound, "malformed", "no such authorization")
		return
	}

	s.attachNonce(r.Context(), w)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     authz.Status,
		"expires":    authz.ExpiresAt.UTC().Format(time.RFC3339),
		"identifier": map[string]string{"type": "dns", "value": authz.Identifier},
		"challenges": []any{},
	})
}

type finalizeRequest struct {
	CSR string `json:"csr"`
}

// handleACMEFinalize signs.
//
// The CSR supplies a public key and nothing else that matters. Its subject and
// its SANs are what the client would like; the names on the certificate are the
// ones the order was authorised for, which Cardinal decided from the directory.
func (s *Server) handleACMEFinalize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, ok := s.verify(w, r, true)
	if !ok {
		return
	}
	if s.x509CA == nil {
		s.acmeError(w, r, http.StatusNotImplemented, "serverInternal",
			"this deployment does not issue X.509 certificates")
		return
	}

	order, ok := s.orderForAccount(w, r, req.account)
	if !ok {
		return
	}
	if order.Status != "ready" {
		s.acmeError(w, r, http.StatusForbidden, "orderNotReady",
			"this order is "+order.Status)
		return
	}

	var body finalizeRequest
	if err := json.Unmarshal(req.payload, &body); err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "malformed", "the payload is not JSON")
		return
	}

	der, err := base64.RawURLEncoding.DecodeString(body.CSR)
	if err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "badCSR", "the CSR is not base64url")
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		s.acmeError(w, r, http.StatusBadRequest, "badCSR", "the CSR does not parse")
		return
	}
	if err := csr.CheckSignature(); err != nil {
		// A CSR whose signature does not verify proves nothing about who holds
		// the private key, which is the only thing a CSR is for.
		s.acmeError(w, r, http.StatusBadRequest, "badCSR",
			"the CSR is not signed by the key it carries")
		return
	}

	certificate, serial, caKeyID, err := s.signLeaf(ctx, csr, order.Identifiers)
	if err != nil {
		s.log.ErrorContext(ctx, "acme: signing failed", "error", err,
			"subject", req.account.Subject)
		s.acmeError(w, r, http.StatusInternalServerError, "serverInternal",
			"could not issue the certificate")
		return
	}

	if err := s.store.FinaliseACMEOrder(ctx, order.ID, caKeyID,
		req.account.SubjectID, certificate, serial); err != nil {
		s.log.ErrorContext(ctx, "acme: recording issuance failed", "error", err)
		s.acmeError(w, r, http.StatusInternalServerError, "serverInternal",
			"could not record the certificate")
		return
	}

	s.log.InfoContext(ctx, "x509 certificate issued",
		"subject", req.account.Subject, "names", order.Identifiers, "serial", serial)

	updated, err := s.store.ACMEOrderByID(ctx, order.ID)
	if err != nil {
		s.acmeError(w, r, http.StatusInternalServerError, "serverInternal",
			"could not read back the order")
		return
	}

	s.attachNonce(ctx, w)
	w.Header().Set("Location", s.acmeURL("/order/"+order.ID.String()))
	writeJSON(w, http.StatusOK, s.orderJSON(updated))
}

// handleACMECertificate returns the chain, PEM.
func (s *Server) handleACMECertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, ok := s.verify(w, r, true)
	if !ok {
		return
	}

	order, ok := s.orderForAccount(w, r, req.account)
	if !ok {
		return
	}
	if len(order.Certificate) == 0 {
		s.acmeError(w, r, http.StatusNotFound, "malformed",
			"this order has no certificate")
		return
	}

	chain, err := s.x509CA.Chain(ctx)
	if err != nil {
		s.acmeError(w, r, http.StatusInternalServerError, "serverInternal",
			"could not read the authority chain")
		return
	}

	var out strings.Builder
	// The leaf first, then everything above it — the order every TLS
	// implementation expects, and the one a client will hand straight to a
	// server without reordering.
	_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: order.Certificate})
	for _, above := range chain {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: above.Raw})
	}

	s.attachNonce(ctx, w)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = io.WriteString(w, out.String())
}

func (s *Server) orderForAccount(w http.ResponseWriter, r *http.Request, account *store.ACMEAccount) (*store.ACMEOrder, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.acmeError(w, r, http.StatusNotFound, "malformed", "no such order")
		return nil, false
	}

	order, err := s.store.ACMEOrderByID(r.Context(), id)
	if err != nil || order.AccountID != account.ID {
		s.acmeError(w, r, http.StatusNotFound, "malformed", "no such order")
		return nil, false
	}
	return order, true
}

// bindAccount verifies an external account binding.
//
// Returns which host it belongs to and the account key it vouches for — both,
// because they are one answer. An earlier version returned the key and stashed
// the subject in a map for a second function to pick up, which is two requests'
// worth of state living between two lines of one.
//
// The credential is spent by reading it, so a binding replayed a second time
// finds nothing.
func (s *Server) bindAccount(
	ctx context.Context, binding json.RawMessage,
) (subjectID uuid.UUID, accountKey []byte, err error) {
	// The key id has to be read before the signature can be checked, because it
	// names the key the signature is checked *with*. Nothing is trusted from
	// this read except which credential to look up.
	var probe struct {
		Protected string `json:"protected"`
	}
	if err := json.Unmarshal(binding, &probe); err != nil {
		return uuid.Nil, nil, errors.New("binding is not a JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(probe.Protected)
	if err != nil {
		return uuid.Nil, nil, errors.New("binding header is not base64url")
	}
	var header struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return uuid.Nil, nil, errors.New("binding header is not JSON")
	}

	subjectID, macKey, err := s.store.RedeemEABCredential(ctx, header.KID, s.x509CA.SealKey())
	if err != nil {
		return uuid.Nil, nil, err
	}

	if _, accountKey, err = acme.VerifyEAB(binding, macKey, s.acmeURL("/new-account")); err != nil {
		return uuid.Nil, nil, err
	}
	return subjectID, accountKey, nil
}

// signLeaf issues the certificate.
func (s *Server) signLeaf(
	ctx context.Context, csr *x509.CertificateRequest, names []string,
) (der []byte, serial string, caKeyID uuid.UUID, err error) {
	key, err := s.x509CA.Active(ctx)
	if err != nil {
		return nil, "", uuid.Nil, err
	}

	number, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", uuid.Nil, fmt.Errorf("generating a serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: number,
		// The first authorised name, because a CN is still read by enough old
		// software to be worth filling in — and because leaving it empty makes
		// a certificate look broken in every inspection tool.
		Subject:  csr.Subject,
		DNSNames: names,

		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(DefaultLeafValidity),

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		// Both, because a host certificate is used in both directions: a server
		// presenting itself, and the same machine authenticating to something
		// else with the same key.
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	template.Subject.CommonName = names[0]

	der, err = x509.CreateCertificate(rand.Reader, template, key.Certificate,
		csr.PublicKey, key.Signer())
	if err != nil {
		return nil, "", uuid.Nil, fmt.Errorf("signing: %w", err)
	}
	return der, acme.SerialString(number), key.ID, nil
}
