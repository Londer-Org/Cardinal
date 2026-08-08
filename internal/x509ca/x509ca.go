// Package x509ca is the X.509 certificate authority.
//
// Thin on purpose. The store holds the keys and does the sealing, crypto/x509
// does the encoding, and what is left here is the one thing neither of those
// can own: holding the encryption key that opens the authority, and keeping it
// somewhere the rest of the server cannot casually reach.
//
// The same shape as internal/sshca, and the same reasoning (ADR 0021). Whoever
// holds this key can issue a certificate for any name the fleet trusts, so it
// lives behind one object with a small surface rather than being a string
// passed around.
package x509ca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"go.londer.be/cardinal/internal/store"
)

// CA issues certificates with the directory's active authority key.
type CA struct {
	store *store.Store

	// seal opens the sealed private key. Its own value, separate from the OIDC
	// signer's and from the SSH authority's — one leaked configuration file
	// must not yield more than one of them (ADR 0021).
	seal string
}

// New builds a CA.
func New(s *store.Store, encryptionKey string) (*CA, error) {
	if encryptionKey == "" {
		return nil, errors.New("x509ca: no encryption key — the authority key is " +
			"not stored in the clear, so it cannot be read without one")
	}
	return &CA{store: s, seal: encryptionKey}, nil
}

// SealKey is the encryption key, for the few callers that need to open
// something else sealed with it.
//
// Exported reluctantly and used in exactly one place: external account binding
// credentials, which are sealed with the same key because they are part of the
// same subsystem and a second encryption key for them would be a second thing
// to rotate for no separation gained.
func (c *CA) SealKey() string { return c.seal }

// Active returns the key that signs, with its private half.
func (c *CA) Active(ctx context.Context) (*store.X509CAKey, error) {
	key, err := c.store.ActiveX509CAKey(ctx, c.seal)
	if err != nil {
		return nil, err
	}
	if key.Signer() == nil {
		return nil, errors.New("x509ca: the active key cannot sign")
	}
	return key, nil
}

// Chain is what a client must be given alongside a leaf.
//
// The active key's own certificate first, then everything above it. Not the
// root: a client that does not already trust the root will not be persuaded by
// the server sending it, and including it wastes bytes on every handshake.
func (c *CA) Chain(ctx context.Context) ([]*x509.Certificate, error) {
	key, err := c.store.ActiveX509CAKey(ctx, c.seal)
	if err != nil {
		return nil, err
	}

	out := []*x509.Certificate{key.Certificate}
	out = append(out, key.Chain...)

	// When the active key *is* the root, the chain is just itself — and a leaf
	// should not be served with it for the same reason. Dropping it here rather
	// than at the caller keeps "what goes on the wire" one decision.
	if len(key.Chain) == 0 && isSelfSigned(key.Certificate) {
		return nil, nil
	}
	return out, nil
}

// Roots is what has to reach every trust store.
//
// The hard part of an internal CA, and the part no code can do: this returns
// the certificates, and getting them into system stores, container images, JVM
// keystores and browsers is somebody's afternoon.
func (c *CA) Roots(ctx context.Context) ([]*store.X509CAKey, error) {
	keys, err := c.store.TrustedX509CAKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("x509ca: reading trusted keys: %w", err)
	}
	return keys, nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}
