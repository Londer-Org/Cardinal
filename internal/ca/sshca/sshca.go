// Package sshca issues short-lived SSH user certificates.
//
// This is Cardinal's answer to "may this person log into this host, and as
// whom" (ADR 0006). The answer is given once, at issuance, and encoded in a
// certificate that `sshd` verifies with nothing but a signature — no directory
// lookup at login, no network call, no Kerberos.
//
// Three properties follow from that, and they are the reason for the design
// rather than side effects:
//
//   - **Host access survives a Cardinal outage.** A certificate already issued
//     keeps working. SSH is the one path built to outlive the identity provider,
//     which matters most precisely when something is wrong.
//
//   - **A compromised host cannot enumerate the directory**, because it never
//     talks to it. SSSD's model hands every host a credential that can read
//     everything; this one hands it a public key.
//
//   - **Access expires by itself.** Minutes, not the lifetime of an account
//     nobody remembered to close.
package sshca

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/store"
	"golang.org/x/crypto/ssh"
)

// DefaultValidity is how long an issued certificate lives.
//
// Short enough that a stolen one is not durable access, long enough to finish
// what you started. Configurable per issuance for the cases that genuinely
// differ; ten minutes is the default because five is disruptive on a slow link
// and an hour stops being short-lived in any useful sense.
const DefaultValidity = 10 * time.Minute

// clockSkew is subtracted from the start time.
//
// Hosts do not agree with Cardinal about the time to the second, and a
// certificate that is not yet valid is refused with a message nobody can act
// on. The threat model already assumes working NTP; this covers the ordinary
// drift NTP leaves behind, not a broken clock.
const clockSkew = 60 * time.Second

// Request is what to issue and for whom.
type Request struct {
	// SubjectID is the person the certificate is for.
	SubjectID uuid.UUID

	// Login is their directory name, used in the certificate's key id so that
	// `sshd` logs say who this was rather than printing a UUID.
	Login string

	// PublicKey is the key the user holds. Cardinal never sees the private
	// half, which is the point: a certificate authority that generated user
	// keys would be a place every user's key had once existed.
	PublicKey ssh.PublicKey

	// Principals are the local accounts this certificate may become. Derived
	// from policy by the caller, never taken from the requester — a client
	// asking to be `root` is a request, not an entitlement.
	Principals []string

	// HostID records which host the request was about, when it was about one.
	HostID *uuid.UUID

	// Validity overrides DefaultValidity when non-zero.
	Validity time.Duration
}

// HostRequest is a machine asking Cardinal to vouch for its name.
type HostRequest struct {
	// HostID is the directory entity. Recorded so that "which machine held a
	// certificate for git.example.com in March" is answerable.
	HostID uuid.UUID

	// Name is the host's directory name, for the certificate's key id.
	Name string

	// PublicKey is the machine's existing SSH host key. Deliberately not the
	// key it authenticates to Cardinal with: that one is Cardinal's business and
	// this one is already presented to every stranger who connects to port 22,
	// so keeping them separate means a compromise of either is not both.
	PublicKey ssh.PublicKey

	// Principals are the names this certificate is good for, from the
	// directory. Never from the request — a machine asking for a certificate
	// naming git.example.com is asking to be git.example.com.
	Principals []string

	// Validity overrides DefaultHostValidity when non-zero.
	Validity time.Duration
}

// DefaultHostValidity is how long a host certificate lasts.
//
// Days rather than the minutes a user certificate gets, and the asymmetry is
// deliberate. A user certificate expiring costs one person one `cardinal ssh`;
// a host certificate expiring costs every user of that machine a TOFU prompt at
// once, during whatever is already going wrong. Seven days means Cardinal can be
// unreachable for a week before anybody notices, and the agent renews at a third
// of that.
//
// Not longer, because there is no revocation. A decommissioned machine keeps
// being able to prove its name until the certificate expires, and a week of that
// is a bounded problem where a year of it is not.
const DefaultHostValidity = 7 * 24 * time.Hour

// IssueHost signs a machine's host key.
//
// Separate from Issue rather than a flag on it, because almost every rule
// differs: no extensions, principals that are names rather than accounts, a
// validity measured in days, and a certificate type that OpenSSH will refuse to
// use for the other purpose. Conflating them would make it possible to issue a
// user certificate carrying a hostname, or a host certificate carrying
// permit-pty, and neither would look wrong in a diff.
func (c *CA) IssueHost(ctx context.Context, req HostRequest) (*ssh.Certificate, error) {
	if req.PublicKey == nil {
		return nil, errors.New("sshca: no host key to sign")
	}
	if len(req.Principals) == 0 {
		// Same trap as a user certificate, and worse here: OpenSSH reads an
		// empty principal list on a host certificate as "valid for every
		// hostname", so this would mint a certificate that authenticates as
		// anything at all.
		return nil, errors.New("sshca: refusing to issue a host certificate with no principals")
	}

	key, err := c.store.ActiveSSHCAKey(ctx, c.seal)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.NewSignerFromSigner(key.Signer())
	if err != nil {
		return nil, fmt.Errorf("sshca: preparing the authority key: %w", err)
	}

	cert, err := SignHostCertificate(signer, req)
	if err != nil {
		return nil, err
	}
	serial := cert.Serial

	if err := c.store.RecordSSHCertificate(ctx, &store.SSHCertificateRecord{
		Serial: serial,
		// The host is both the subject and the host here, which reads oddly and
		// is correct: the certificate is about the machine itself rather than
		// about somebody's access to it.
		SubjectID:  req.HostID,
		HostID:     &req.HostID,
		Principals: req.Principals,
		CAKeyID:    key.ID,
		KeyID:      cert.KeyId,
		ExpiresAt:  goTime(cert.ValidBefore),
	}); err != nil {
		return nil, err
	}

	return cert, nil
}

// SignHostCertificate builds and signs the certificate itself.
//
// Split out from IssueHost so the construction can be exercised without a
// database — which is what `make verify-host` needs to hand a real OpenSSH
// client a real certificate from this code rather than one built by ssh-keygen
// to look like it. Testing our signer against our own verifier is the trap this
// project has hit before.
func SignHostCertificate(signer ssh.Signer, req HostRequest) (*ssh.Certificate, error) {
	if req.PublicKey == nil {
		return nil, errors.New("sshca: no host key to sign")
	}
	if len(req.Principals) == 0 {
		return nil, errors.New("sshca: refusing to issue a host certificate with no principals")
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	validity := req.Validity
	if validity <= 0 {
		validity = DefaultHostValidity
	}
	now := time.Now()

	cert := &ssh.Certificate{
		Key:             req.PublicKey,
		Serial:          serial,
		CertType:        ssh.HostCert,
		KeyId:           req.Name + "@cardinal",
		ValidPrincipals: req.Principals,
		ValidAfter:      sshTime(now.Add(-clockSkew)),
		ValidBefore:     sshTime(now.Add(validity)),
		// No extensions and no critical options. Everything OpenSSH defines for
		// a host certificate — force-command, source-address — belongs to the
		// user side of the connection, and a host certificate carrying them is
		// at best ignored and at worst a surprise.
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("sshca: signing host certificate: %w", err)
	}
	return cert, nil
}

// CA signs certificates with the directory's active authority key.
type CA struct {
	store *store.Store
	seal  string
}

// New returns a CA backed by the store's active key.
func New(s *store.Store, sealKey string) *CA {
	return &CA{store: s, seal: sealKey}
}

// Issue signs a certificate.
//
// Deliberately does *not* evaluate policy. Whether this person may log into
// this host is a Cedar decision, and it belongs at the call site with the rest
// of the decision points so that it is logged the same way and cannot be
// skipped by a second caller appearing later. This function's contract is
// narrow: given a decision already made, produce the credential that encodes
// it.
func (c *CA) Issue(ctx context.Context, req Request) (*ssh.Certificate, error) {
	if req.PublicKey == nil {
		return nil, errors.New("sshca: no public key to sign")
	}
	if len(req.Principals) == 0 {
		// A certificate with no principals is valid and useless: OpenSSH treats
		// an empty list as "any principal", which would turn a policy decision
		// that produced nothing into unrestricted access.
		return nil, errors.New("sshca: refusing to issue a certificate with no principals")
	}

	key, err := c.store.ActiveSSHCAKey(ctx, c.seal)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.NewSignerFromSigner(key.Signer())
	if err != nil {
		return nil, fmt.Errorf("sshca: preparing the authority key: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	validity := req.Validity
	if validity <= 0 {
		validity = DefaultValidity
	}
	now := time.Now()

	cert := &ssh.Certificate{
		Key:             req.PublicKey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           req.Login + "@cardinal",
		ValidPrincipals: req.Principals,
		ValidAfter:      sshTime(now.Add(-clockSkew)),
		ValidBefore:     sshTime(now.Add(validity)),
		Permissions: ssh.Permissions{
			// Every extension is opt-in. OpenSSH's default for a certificate
			// with no extensions is to permit nothing, which is the right
			// starting point — agent forwarding and port forwarding are how a
			// compromised jump host reaches further, and neither should appear
			// because a default said so.
			Extensions: map[string]string{
				"permit-pty": "",
			},
		},
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("sshca: signing certificate: %w", err)
	}

	// Recorded after signing and before returning, so a certificate cannot
	// reach a user without the journal knowing it exists.
	if err := c.store.RecordSSHCertificate(ctx, &store.SSHCertificateRecord{
		Serial:     serial,
		SubjectID:  req.SubjectID,
		HostID:     req.HostID,
		Principals: req.Principals,
		CAKeyID:    key.ID,
		KeyID:      cert.KeyId,
		ExpiresAt:  goTime(cert.ValidBefore),
	}); err != nil {
		return nil, err
	}

	return cert, nil
}

// sshTime converts an instant to the seconds-since-epoch an SSH certificate
// carries.
//
// A certificate's validity window is unsigned, and a negative value would wrap
// to an enormous one — a certificate valid until the heat death of the universe
// is precisely the failure short lifetimes exist to prevent. Only reachable
// with a clock set before 1970, which is why it clamps rather than errors: a
// zero window is refused by every verifier, a wrapped one is accepted by all of
// them.
func sshTime(t time.Time) uint64 {
	seconds := t.Unix()
	if seconds < 0 {
		return 0
	}
	return uint64(seconds)
}

// goTime is the inverse, clamped so a certificate claiming to be valid beyond
// the year 292277026596 does not become a negative timestamp in the database.
func goTime(seconds uint64) time.Time {
	if seconds > math.MaxInt64 {
		return time.Unix(math.MaxInt64, 0)
	}
	return time.Unix(int64(seconds), 0)
}

// newSerial returns a random 63-bit serial.
//
// Random rather than sequential: a sequential serial tells anyone holding one
// certificate how many have been issued and roughly when, which is information
// about the organisation that a credential should not carry. Kept under 2^63 so
// it survives the round trip through a signed `bigint` column.
func newSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("sshca: generating serial: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]) >> 1, nil
}
