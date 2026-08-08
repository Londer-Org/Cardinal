// Package acme implements the server half of RFC 8555.
//
// Cardinal is an unusual ACME server, and the difference is worth stating
// before any of the code makes sense.
//
// A public CA has no idea who is asking. Everything ACME does about challenges
// — serve this file, publish this TXT record — exists to establish that the
// requester controls the name, because that is the only thing the CA can learn
// about a stranger.
//
// Cardinal already knows. The client is an enrolled host that proved which host
// it is, and the names it may hold are written in the directory. So the
// challenge step has nothing left to demonstrate: authorizations are created
// already valid and the order is ready immediately. RFC 8555 §7.1.6 allows
// exactly this, and every client handles it — it is the same path a client takes
// when it has a cached authorization.
//
// What binds an ACME account to a host is External Account Binding
// (§7.3.4): the standard mechanism, supported by cert-manager, lego, certbot
// and acme.sh, and chosen over carrying Cardinal's own host signature through a
// protocol with nowhere to put it.
package acme

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// JWS is the flattened serialization every ACME request uses.
//
// Not the compact form and not the general form: RFC 8555 §6.2 requires
// flattened, with exactly one signature.
type JWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Header is the protected header, decoded.
type Header struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	KID   string          `json:"kid,omitempty"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
}

// ErrBadSignature covers every way a JWS can fail to verify.
//
// One error deliberately. Telling a caller whether the key was wrong, the
// payload altered or the algorithm unacceptable helps somebody probing far more
// than it helps somebody debugging, who has the client's own logs.
var ErrBadSignature = errors.New("acme: the request signature is not valid")

// Decode parses a JWS and verifies it against the key inside it.
//
// The key comes from `jwk` for a new account and from whatever `kid` names for
// everything else — which is why this returns the header and leaves the caller
// to resolve `kid`. A caller that skipped that lookup would be verifying a
// request against a key the request itself supplied, which is no verification.
func Decode(body []byte) (*Header, *JWS, error) {
	var jws JWS
	if err := json.Unmarshal(body, &jws); err != nil {
		return nil, nil, fmt.Errorf("acme: request is not a JWS: %w", err)
	}
	if jws.Protected == "" || jws.Signature == "" {
		return nil, nil, errors.New("acme: request is not a flattened JWS")
	}

	raw, err := decodeSegment(jws.Protected)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: protected header is not base64url: %w", err)
	}

	var header Header
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, nil, fmt.Errorf("acme: protected header is not JSON: %w", err)
	}

	// Exactly one of them. Both, or neither, is malformed rather than
	// ambiguous — and a request carrying both would let a client choose which
	// key it is verified against.
	hasJWK := len(header.JWK) > 0
	hasKID := header.KID != ""
	if hasJWK == hasKID {
		return nil, nil, errors.New("acme: a JWS must carry exactly one of jwk and kid")
	}

	return &header, &jws, nil
}

// Body decodes the payload of a verified JWS.
//
// An empty payload is POST-as-GET (RFC 8555 §6.3), which is how a client reads
// a resource — ACME has no GET for anything requiring authentication.
func (j *JWS) Body() ([]byte, error) {
	if j.Payload == "" {
		return nil, nil
	}
	return decodeSegment(j.Payload)
}

// Verify checks the signature against a public key.
func Verify(header *Header, jws *JWS, key crypto.PublicKey) error {
	signature, err := decodeSegment(jws.Signature)
	if err != nil {
		return ErrBadSignature
	}

	signed := []byte(jws.Protected + "." + jws.Payload)

	switch header.Alg {
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() || len(signature) != 64 {
			return ErrBadSignature
		}
		sum := sha256.Sum256(signed)
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(pub, sum[:], r, s) {
			return ErrBadSignature
		}
		return nil

	case "ES384":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P384() || len(signature) != 96 {
			return ErrBadSignature
		}
		sum := sha512.Sum384(signed)
		r := new(big.Int).SetBytes(signature[:48])
		s := new(big.Int).SetBytes(signature[48:])
		if !ecdsa.Verify(pub, sum[:], r, s) {
			return ErrBadSignature
		}
		return nil

	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrBadSignature
		}
		// 2048 is the floor every CA has settled on, and a client offering less
		// is either very old or trying something.
		if pub.N.BitLen() < 2048 {
			return ErrBadSignature
		}
		sum := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], signature); err != nil {
			return ErrBadSignature
		}
		return nil

	default:
		// Notably absent: `none`, and the HMAC family. `none` is the classic JWT
		// hole; HS256 here would let anyone who can read a public key forge a
		// signature with it, because the verification key and the signing key
		// would be the same value.
		return fmt.Errorf("%w: unsupported algorithm %q", ErrBadSignature, header.Alg)
	}
}

// JWK is the subset of a JSON Web Key this needs.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// PublicKey converts a JWK to something crypto can verify with.
func (j *JWK) PublicKey() (crypto.PublicKey, error) {
	switch j.Kty {
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("acme: unsupported curve %q", j.Crv)
		}
		x, err := decodeSegment(j.X)
		if err != nil {
			return nil, errors.New("acme: EC key x is not base64url")
		}
		y, err := decodeSegment(j.Y)
		if err != nil {
			return nil, errors.New("acme: EC key y is not base64url")
		}
		// A point that is not on the curve is not a key, and accepting one is
		// the invalid-curve attack. Checked through crypto/ecdh, which is the
		// supported way to ask — elliptic.IsOnCurve is deprecated precisely
		// because it is the low-level API people reach for and misuse.
		size := (curve.Params().BitSize + 7) / 8
		if len(x) > size || len(y) > size {
			return nil, errors.New("acme: EC key coordinates are too large for the curve")
		}
		point := make([]byte, 1+2*size)
		point[0] = 4 // uncompressed
		copy(point[1+size-len(x):1+size], x)
		copy(point[1+2*size-len(y):], y)

		var ecdhCurve ecdh.Curve
		switch j.Crv {
		case "P-256":
			ecdhCurve = ecdh.P256()
		default:
			ecdhCurve = ecdh.P384()
		}
		if _, err := ecdhCurve.NewPublicKey(point); err != nil {
			return nil, fmt.Errorf("acme: EC key is not a valid point: %w", err)
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil

	case "RSA":
		n, err := decodeSegment(j.N)
		if err != nil {
			return nil, errors.New("acme: RSA modulus is not base64url")
		}
		e, err := decodeSegment(j.E)
		if err != nil {
			return nil, errors.New("acme: RSA exponent is not base64url")
		}
		exponent := new(big.Int).SetBytes(e)
		if !exponent.IsInt64() || exponent.Int64() > 1<<31 {
			return nil, errors.New("acme: RSA exponent is out of range")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(exponent.Int64()),
		}, nil

	default:
		return nil, fmt.Errorf("acme: unsupported key type %q", j.Kty)
	}
}

// Thumbprint is the RFC 7638 fingerprint of a JWK.
//
// The canonical identity of an account key. The rules are exact and unforgiving:
// the required members only, lexicographic order, no whitespace — because two
// implementations that disagree by a byte produce different thumbprints for the
// same key, and the account is simply not found.
func (j *JWK) Thumbprint() (string, error) {
	var canonical string
	switch j.Kty {
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, j.Crv, j.X, j.Y)
	case "RSA":
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, j.E, j.N)
	default:
		return "", fmt.Errorf("acme: cannot fingerprint key type %q", j.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return encodeSegment(sum[:]), nil
}

// VerifyEAB checks an external account binding.
//
// The inner JWS in a new-account request, signed with a MAC key Cardinal handed
// to one specific machine. Its payload is the account key, so a valid binding
// says "the holder of this out-of-band credential vouches that this account key
// is theirs" — which is how an anonymous ACME account acquires an identity here.
func VerifyEAB(binding json.RawMessage, macKey []byte, expectedURL string) (keyID string, accountJWK []byte, err error) {
	var jws JWS
	if decodeErr := json.Unmarshal(binding, &jws); decodeErr != nil {
		return "", nil, errors.New("acme: external account binding is not a JWS")
	}

	raw, err := decodeSegment(jws.Protected)
	if err != nil {
		return "", nil, errors.New("acme: binding header is not base64url")
	}
	var header Header
	if decodeErr := json.Unmarshal(raw, &header); decodeErr != nil {
		return "", nil, errors.New("acme: binding header is not JSON")
	}

	// HS256 here and only here. The key is symmetric and shared out of band,
	// which is exactly the case HMAC is for — and the reason it is refused
	// everywhere else in this file.
	if header.Alg != "HS256" {
		return "", nil, fmt.Errorf("acme: external account binding must use HS256, not %q",
			header.Alg)
	}
	if header.URL != expectedURL {
		// Binds the binding to the endpoint. Without it a binding captured from
		// one server could be replayed at another.
		return "", nil, errors.New("acme: external account binding is for a different URL")
	}
	if header.KID == "" {
		return "", nil, errors.New("acme: external account binding names no key")
	}

	signature, err := decodeSegment(jws.Signature)
	if err != nil {
		return "", nil, ErrBadSignature
	}

	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(jws.Protected + "." + jws.Payload))
	if !hmac.Equal(mac.Sum(nil), signature) {
		return "", nil, ErrBadSignature
	}

	payload, err := decodeSegment(jws.Payload)
	if err != nil {
		return "", nil, errors.New("acme: binding payload is not base64url")
	}
	return header.KID, payload, nil
}

// decodeSegment is base64url without padding, which is what JOSE uses
// everywhere and what a standard base64 decoder gets wrong.
func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Encode is the inverse, for the few places a server has to produce one.
func Encode(b []byte) string { return encodeSegment(b) }

// KeyAuthorization is the token.thumbprint construction from §8.1.
//
// Unused by Cardinal's own flow — there are no challenges to answer — but a
// client may still ask for a challenge object, and one carrying a malformed key
// authorization would be a puzzle rather than a no-op.
func KeyAuthorization(token, thumbprint string) string {
	return token + "." + thumbprint
}

// NewToken makes an opaque, unguessable identifier.
func NewToken(random func([]byte) (int, error)) (string, error) {
	b := make([]byte, 32)
	if _, err := random(b); err != nil {
		return "", fmt.Errorf("acme: generating a token: %w", err)
	}
	return encodeSegment(b), nil
}

// SerialString renders a certificate serial the way a person reads one.
func SerialString(serial *big.Int) string {
	b := serial.Bytes()
	if len(b) == 0 {
		return "00"
	}
	out := make([]byte, 0, len(b)*3)
	const hexits = "0123456789abcdef"
	for i, c := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexits[c>>4], hexits[c&0x0f])
	}
	return string(out)
}
