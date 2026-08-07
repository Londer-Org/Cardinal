package acme_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/arthur-lonfils/cardinal/internal/acme"
)

// TestThumbprintIsStableAndDistinct.
//
// Deliberately *not* the RFC 7638 §3.1 test vector, which is what this started
// as. Its modulus is a 342-character base64 string, transcribing it from memory
// produced a value that hashed to something else entirely, and a test asserting
// a constant nobody can check is worse than no test — it looks like external
// validation and is not.
//
// What validates the canonicalisation is `make verify-acme`: lego computes the
// thumbprint of its own account key independently, and every request it makes
// afterwards is looked up by it. An account that could not be found would fail
// on the first order, which is the same assertion made by somebody else's code.
//
// What a unit test can honestly say is here.
func TestThumbprintIsStableAndDistinct(t *testing.T) {
	first, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	a, b := testJWK(t, first), testJWK(t, second)

	one, err := a.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if one != again {
		t.Fatal("the same key produced two thumbprints")
	}

	other, err := b.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if one == other {
		t.Fatal("two different keys share a thumbprint")
	}

	// SHA-256, base64url, unpadded.
	if len(one) != 43 {
		t.Fatalf("a thumbprint is %d characters, want 43", len(one))
	}
	if strings.ContainsAny(one, "+/=") {
		t.Fatalf("a thumbprint is not base64url: %q", one)
	}
}

// signES256 produces a JWS the way a client would.
func signES256(t *testing.T, key *ecdsa.PrivateKey, protected, payload string) *acme.JWS {
	t.Helper()

	p := base64.RawURLEncoding.EncodeToString([]byte(protected))
	pl := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sum := sha256.Sum256([]byte(p + "." + pl))

	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	return &acme.JWS{
		Protected: p, Payload: pl,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

func testJWK(t *testing.T, key *ecdsa.PrivateKey) acme.JWK {
	t.Helper()
	return acme.JWK{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
}

// TestASignatureVerifiesAndATamperedOneDoesNot.
func TestASignatureVerifiesAndATamperedOneDoesNot(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := testJWK(t, key)
	public, err := jwk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	protected := `{"alg":"ES256","nonce":"abc","url":"https://id.example/acme/new-order"}`
	jws := signES256(t, key, protected, `{"identifiers":[]}`)
	header := &acme.Header{Alg: "ES256"}

	if err := acme.Verify(header, jws, public); err != nil {
		t.Fatalf("a correct signature did not verify: %v", err)
	}

	// One byte of payload. Without this the test above would pass against a
	// verifier that checked nothing.
	tampered := *jws
	tampered.Payload = base64.RawURLEncoding.EncodeToString([]byte(`{"identifiers":["x"]}`))
	if err := acme.Verify(header, &tampered, public); err == nil {
		t.Fatal("an altered payload verified")
	}
}

// TestUnsafeAlgorithmsAreRefused.
//
// `none` is the classic JWT hole. HS256 here would be worse: the verification
// key and the signing key would be the same value, so anyone who can read a
// public key could forge a signature with it.
func TestUnsafeAlgorithmsAreRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := testJWK(t, key)
	public, err := jwk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	jws := signES256(t, key, `{"alg":"none"}`, "{}")

	for _, alg := range []string{"none", "HS256", "ES512", ""} {
		t.Run(alg, func(t *testing.T) {
			if err := acme.Verify(&acme.Header{Alg: alg}, jws, public); err == nil {
				t.Fatalf("%q was accepted", alg)
			}
		})
	}
}

// TestAJWSMustCarryExactlyOneOfJWKAndKID.
//
// Both would let a client choose which key it is verified against, which is the
// same as not being verified.
func TestAJWSMustCarryExactlyOneOfJWKAndKID(t *testing.T) {
	for _, tc := range []struct {
		name      string
		protected string
		ok        bool
	}{
		{"jwk only", `{"alg":"ES256","jwk":{"kty":"EC"},"nonce":"n","url":"u"}`, true},
		{"kid only", `{"alg":"ES256","kid":"https://x/acme/account/1","nonce":"n","url":"u"}`, true},
		{"both", `{"alg":"ES256","jwk":{"kty":"EC"},"kid":"k","nonce":"n","url":"u"}`, false},
		{"neither", `{"alg":"ES256","nonce":"n","url":"u"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(acme.JWS{
				Protected: base64.RawURLEncoding.EncodeToString([]byte(tc.protected)),
				Payload:   "",
				Signature: "AA",
			})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = acme.Decode(body)
			if tc.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestAnECKeyOffItsCurveIsRefused.
//
// The invalid-curve attack. A point that is not on the curve is not a key, and
// accepting one lets an attacker learn things about a private key it is used
// against.
func TestAnECKeyOffItsCurveIsRefused(t *testing.T) {
	jwk := acme.JWK{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(big.NewInt(1).FillBytes(make([]byte, 32))),
		Y: base64.RawURLEncoding.EncodeToString(big.NewInt(1).FillBytes(make([]byte, 32))),
	}
	if _, err := jwk.PublicKey(); err == nil {
		t.Fatal("a point off the curve was accepted as a key")
	}
}

// TestExternalAccountBinding.
//
// The mechanism that turns an anonymous ACME account into one belonging to a
// specific host. Three ways it must fail, and each is somebody trying something
// rather than a client misbehaving.
func TestExternalAccountBinding(t *testing.T) {
	macKey := []byte("a-fixture-mac-key-of-adequate-length")
	const url = "https://id.example/acme/new-account"
	accountKey := `{"kty":"EC","crv":"P-256","x":"AA","y":"BB"}`

	sign := func(protected, payload string, key []byte) json.RawMessage {
		p := base64.RawURLEncoding.EncodeToString([]byte(protected))
		pl := base64.RawURLEncoding.EncodeToString([]byte(payload))
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(p + "." + pl))
		out, err := json.Marshal(acme.JWS{
			Protected: p, Payload: pl,
			Signature: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	good := `{"alg":"HS256","kid":"credential-1","url":"` + url + `"}`

	t.Run("valid", func(t *testing.T) {
		kid, key, err := acme.VerifyEAB(sign(good, accountKey, macKey), macKey, url)
		if err != nil {
			t.Fatal(err)
		}
		if kid != "credential-1" {
			t.Fatalf("kid %q", kid)
		}
		if string(key) != accountKey {
			t.Fatalf("the bound key is %q", key)
		}
	})

	t.Run("wrong mac key", func(t *testing.T) {
		_, _, err := acme.VerifyEAB(sign(good, accountKey, []byte("somebody else's key")),
			macKey, url)
		if err == nil {
			t.Fatal("a binding signed with the wrong key was accepted")
		}
	})

	t.Run("captured from another server", func(t *testing.T) {
		other := `{"alg":"HS256","kid":"credential-1","url":"https://elsewhere/acme/new-account"}`
		_, _, err := acme.VerifyEAB(sign(other, accountKey, macKey), macKey, url)
		if err == nil {
			t.Fatal("a binding for a different URL was accepted")
		}
	})

	t.Run("algorithm swapped", func(t *testing.T) {
		swapped := `{"alg":"none","kid":"credential-1","url":"` + url + `"}`
		_, _, err := acme.VerifyEAB(sign(swapped, accountKey, macKey), macKey, url)
		if err == nil {
			t.Fatal("a binding with alg none was accepted")
		}
	})
}

// TestSerialString renders the way a person reads one.
func TestSerialString(t *testing.T) {
	got := acme.SerialString(big.NewInt(0x0a1b2c))
	if got != "0a:1b:2c" {
		t.Fatalf("got %q", got)
	}
	if acme.SerialString(big.NewInt(0)) != "00" {
		t.Fatal("a zero serial should still render")
	}
	if strings.Count(acme.SerialString(big.NewInt(255)), ":") != 0 {
		t.Fatal("a one-byte serial should have no separator")
	}
}
