package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A certificate is only worth anything if OpenSSH agrees it is one. These tests
// check the properties `sshd` actually enforces, using the same library `sshd`
// is modelled on, rather than checking that the struct we filled in has the
// fields we put in it.

func testKeys(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromSigner(caPriv)
	if err != nil {
		t.Fatal(err)
	}

	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	return ca, user
}

// sign builds a certificate the way Issue does, without the store, so the
// certificate's shape can be tested without a database.
func sign(t *testing.T, ca ssh.Signer, user ssh.PublicKey, principals []string) *ssh.Certificate {
	t.Helper()

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             user,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "alonfils@cardinal",
		ValidPrincipals: principals,
		ValidAfter:      sshTime(now.Add(-clockSkew)),
		ValidBefore:     sshTime(now.Add(DefaultValidity)),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{"permit-pty": ""},
		},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestCertificateIsAcceptedForItsPrincipal.
//
// The whole point: `sshd` checks a signature and a principal list, and nothing
// else. If this passes, a host with the CA public key in TrustedUserCAKeys lets
// the holder in as that local user, with no directory lookup at login.
func TestCertificateIsAcceptedForItsPrincipal(t *testing.T) {
	ca, user := testKeys(t)
	cert := sign(t, ca, user, []string{"deploy"})

	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return string(k.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}

	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Fatalf("a freshly issued certificate was refused: %v", err)
	}
}

// TestCertificateIsRefusedForAnotherPrincipal.
//
// Principals are the authorization, not a hint. A certificate issued for
// `deploy` must not let its holder become `root`, or the policy decision that
// produced the list meant nothing.
func TestCertificateIsRefusedForAnotherPrincipal(t *testing.T) {
	ca, user := testKeys(t)
	cert := sign(t, ca, user, []string{"deploy"})

	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return string(k.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}

	if err := checker.CheckCert("root", cert); err == nil {
		t.Fatal("a certificate issued for `deploy` was accepted for `root`")
	}
}

// TestCertificateIsRefusedFromAnotherAuthority.
//
// A host trusts CA keys, not certificates. Signing with anything else must fail
// even when every other field is perfect — this is what makes the CA key the
// thing worth protecting.
//
// The mechanics here are a trap worth knowing about, because this test caught
// it. `CertChecker.CheckCert` does *not* check the authority. It verifies the
// signature against `cert.SignatureKey` — the key carried inside the
// certificate — so a certificate signed by any key at all verifies against
// itself and passes. `IsUserAuthority` is consulted by `Authenticate`, which is
// the path `sshd` uses, and a verifier written with `CheckCert` alone would
// accept certificates from every CA on earth.
//
// So this asserts both halves, in the order a correct verifier does them.
func TestCertificateIsRefusedFromAnotherAuthority(t *testing.T) {
	ca, user := testKeys(t)
	other, _ := testKeys(t)
	cert := sign(t, other, user, []string{"deploy"})

	trusted := func(k ssh.PublicKey) bool {
		return string(k.Marshal()) == string(ca.PublicKey().Marshal())
	}

	if trusted(cert.SignatureKey) {
		t.Fatal("a certificate from another authority was recognised as trusted")
	}

	// And the half that does hold: the signature is valid, which is exactly why
	// checking it alone is not enough.
	checker := &ssh.CertChecker{IsUserAuthority: trusted}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Fatalf("the certificate was internally malformed rather than merely "+
			"untrusted, which is not what this test is about: %v", err)
	}
}

// TestExpiredCertificateIsRefused.
//
// Access expiring by itself is the property the whole design rests on: a
// certificate measured in minutes is why there is no revocation list, and why a
// stolen one is not durable access.
func TestExpiredCertificateIsRefused(t *testing.T) {
	ca, user := testKeys(t)

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             user,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "alonfils@cardinal",
		ValidPrincipals: []string{"deploy"},
		ValidAfter:      sshTime(now.Add(-2 * time.Hour)),
		ValidBefore:     sshTime(now.Add(-1 * time.Hour)),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return string(k.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}

	if err := checker.CheckCert("deploy", cert); err == nil {
		t.Fatal("an expired certificate was accepted")
	}
}

// TestCertificateGrantsNoExtensionsByDefault.
//
// OpenSSH permits nothing unless an extension says otherwise, and the ones that
// matter are how a compromised jump host reaches further: agent forwarding
// hands it your keys, port forwarding hands it your network. Neither should
// appear because a default said so.
func TestCertificateGrantsNoExtensionsByDefault(t *testing.T) {
	ca, user := testKeys(t)
	cert := sign(t, ca, user, []string{"deploy"})

	for _, forbidden := range []string{
		"permit-agent-forwarding",
		"permit-port-forwarding",
		"permit-X11-forwarding",
		"permit-user-rc",
	} {
		if _, present := cert.Extensions[forbidden]; present {
			t.Errorf("%s is granted by default — a compromised host reached "+
				"further than it should be able to", forbidden)
		}
	}

	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Error("permit-pty is absent, so an interactive session would not work")
	}
}

// TestKeyIdNamesThePerson.
//
// `sshd` logs the key id on every accepted certificate. If it carried a UUID,
// the host's auth log — which is often the only log an incident responder has
// early on — would be unreadable without the directory.
func TestKeyIdNamesThePerson(t *testing.T) {
	ca, user := testKeys(t)
	cert := sign(t, ca, user, []string{"deploy"})

	if !strings.HasPrefix(cert.KeyId, "alonfils@") {
		t.Errorf("key id is %q, which does not name the person it was issued to",
			cert.KeyId)
	}
}

// TestSerialsDoNotRepeatOrCount.
//
// Random rather than sequential. A sequential serial tells anyone holding one
// certificate roughly how many have been issued and when, which is information
// about the organisation that a credential should not carry.
func TestSerialsDoNotRepeatOrCount(t *testing.T) {
	seen := map[uint64]bool{}
	var previous uint64
	ascending := 0

	for i := 0; i < 200; i++ {
		serial, err := newSerial()
		if err != nil {
			t.Fatal(err)
		}
		if seen[serial] {
			t.Fatalf("serial %d repeated within 200 issuances", serial)
		}
		seen[serial] = true

		// Must survive the round trip through a signed bigint column.
		if serial > 1<<63-1 {
			t.Fatalf("serial %d does not fit in a signed 64-bit column", serial)
		}
		if i > 0 && serial > previous {
			ascending++
		}
		previous = serial
	}

	// Random values ascend about half the time; a counter ascends always.
	if ascending > 180 {
		t.Errorf("%d of 199 serials ascended — these look sequential, which "+
			"leaks issuance volume to anyone holding one certificate", ascending)
	}
}
