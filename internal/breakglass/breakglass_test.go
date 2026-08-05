package breakglass

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := DecodePublic(EncodePublic(kp.Public))
	if err != nil {
		t.Fatalf("public key did not round-trip: %v", err)
	}
	priv, err := DecodePrivate(EncodePrivate(kp.Private))
	if err != nil {
		t.Fatalf("private key did not round-trip: %v", err)
	}

	c, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(pub, c.Sign(priv)); err != nil {
		t.Fatalf("a correctly signed challenge was rejected: %v", err)
	}
}

// TestWrongKeyRejected: the obvious attack — an attacker with their own keypair.
func TestWrongKeyRejected(t *testing.T) {
	real, _ := Generate()
	attacker, _ := Generate()

	c, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}

	err = c.Verify(real.Public, c.Sign(attacker.Private))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("a signature from the wrong key was accepted: %v", err)
	}
}

// TestExpiredChallengeRejected: expiry must be checked independently of the
// signature, so a challenge captured from a terminal or a log is worthless by
// the time anyone finds it.
func TestExpiredChallengeRejected(t *testing.T) {
	kp, _ := Generate()

	c := &Challenge{
		Nonce:     make([]byte, challengeSize),
		IssuedAt:  time.Now().Add(-2 * ChallengeTTL),
		ExpiresAt: time.Now().Add(-ChallengeTTL),
	}
	if _, err := rand.Read(c.Nonce); err != nil {
		t.Fatal(err)
	}

	// Signed correctly, but too late.
	err := c.Verify(kp.Public, c.Sign(kp.Private))
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expected expiry rejection, got: %v", err)
	}
}

// TestDomainSeparation is the subtle one.
//
// Cardinal will use Ed25519 elsewhere — SSH certificate issuance, for instance.
// Without a domain-separation prefix, a signature obtained in one protocol
// could be replayed as a break-glass authorisation. The prefix is what keeps
// two individually-safe designs from combining into an unsafe one.
func TestDomainSeparation(t *testing.T) {
	kp, _ := Generate()

	c, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}

	// A signature over the raw nonce, as some other protocol might produce.
	rawSig := base64.StdEncoding.EncodeToString(ed25519.Sign(kp.Private, c.Nonce))

	if err := c.Verify(kp.Public, rawSig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatal("a signature over the bare nonce was accepted — without domain " +
			"separation, a signature from another protocol could authorise break-glass")
	}
}

// TestChallengesAreUnique guards against a nonce generator that repeats, which
// would make signatures replayable.
func TestChallengesAreUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for range 1000 {
		c, err := NewChallenge()
		if err != nil {
			t.Fatal(err)
		}
		enc := c.Encode()
		if seen[enc] {
			t.Fatal("challenge nonce repeated — signatures would be replayable")
		}
		seen[enc] = true
	}
}

func TestMalformedKeysRejected(t *testing.T) {
	cases := []struct{ name, key string }{
		{"empty", ""},
		{"no prefix", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		{"wrong prefix", "ssh-ed25519:AAAA"},
		{"not base64", "cardinal-bg-v1:!!!!not base64!!!!"},
		{"too short", "cardinal-bg-v1:" + base64.StdEncoding.EncodeToString([]byte("short"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodePublic(tc.key); err == nil {
				t.Fatalf("malformed key %q was accepted", tc.key)
			}
		})
	}
}

// TestPrivateKeyIsGreppable: if a break-glass private key ever leaks into a
// repository, a backup, or a chat message, the prefix is what makes automated
// secret scanning find it.
func TestPrivateKeyIsGreppable(t *testing.T) {
	kp, _ := Generate()
	encoded := EncodePrivate(kp.Private)

	if !strings.HasPrefix(encoded, "cardinal-bg-priv-v1:") {
		t.Fatal("private keys must carry a distinctive, scannable prefix")
	}
	if strings.HasPrefix(encoded, "cardinal-bg-v1:") {
		t.Fatal("private and public prefixes must not be confusable — " +
			"mistaking one for the other could publish the private key")
	}
}
