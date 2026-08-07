package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/hostclient"
	"golang.org/x/crypto/ssh"
)

// Vouching for a machine's name.
//
// The property under test is that the names come from the directory and nothing
// else. A compromised host asking for a certificate naming the payments server
// is the attack this endpoint exists to be immune to, so the test asks for
// exactly that.

type certificateResponse struct {
	Certificate string   `json:"certificate"`
	Principals  []string `json:"principals"`
	ExpiresAt   string   `json:"expiresAt"`
	Error       string   `json:"error"`
}

// requestCertificate signs a POST the way the agent does.
func requestCertificate(t *testing.T, identity *hostclient.Identity, body []byte) (int, certificateResponse) {
	t.Helper()

	const path = "/api/hosts/certificate"
	fingerprint := identity.Fingerprint()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	signature, err := identity.Signer.Sign(rand.Reader, []byte(strings.Join([]string{
		"cardinal-host-v1", http.MethodPost, path, timestamp, fingerprint,
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
		"http://"+hostCardinal+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Cardinal-Host %s:%s:%s",
		fingerprint, timestamp,
		base64.StdEncoding.EncodeToString(ssh.Marshal(signature))))

	resp, err := client(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	var out certificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	return resp.StatusCode, out
}

// hostKeyRequest is the body an agent sends: a public key, and nothing else it
// could use to influence the answer.
func hostKeyRequest(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(map[string]string{
		"publicKey": string(ssh.MarshalAuthorizedKey(sshPublic)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body, sshPublic
}

func parseCertificate(t *testing.T, encoded string) *ssh.Certificate {
	t.Helper()

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encoded))
	if err != nil {
		t.Fatalf("the response is not a certificate: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("the response is a public key, not a certificate")
	}
	return cert
}

// TestAHostGetsACertificateForItsDirectoryName.
func TestAHostGetsACertificateForItsDirectoryName(t *testing.T) {
	host := enrolledHost(t, "e2e-cert-01")

	body, publicKey := hostKeyRequest(t)
	status, out := requestCertificate(t, host, body)
	if status != http.StatusOK {
		t.Fatalf("got %d (%s), want 200", status, out.Error)
	}

	cert := parseCertificate(t, out.Certificate)

	if cert.CertType != ssh.HostCert {
		t.Fatalf("got cert type %d, want a host certificate", cert.CertType)
	}
	if !bytes.Equal(cert.Key.Marshal(), publicKey.Marshal()) {
		t.Fatal("the certificate is for a different key than was sent")
	}
	if !slices.Contains(cert.ValidPrincipals, "e2e-cert-01") {
		t.Fatalf("the directory name is missing from %v", cert.ValidPrincipals)
	}

	// A host certificate carrying permit-pty or force-command is at best
	// ignored and at worst a surprise; the user side is where those belong.
	if len(cert.Extensions) != 0 || len(cert.CriticalOptions) != 0 {
		t.Fatalf("a host certificate carries options: %+v", cert.Permissions)
	}

	// Days rather than the minutes a user certificate gets. A host certificate
	// expiring costs every user of that machine a prompt at once.
	//
	// Compared in seconds rather than converted to a Duration: both fields are
	// unsigned, and a Duration is not — a certificate with a wrapped window
	// would come out as a negative life and sail past a `< 24h` check by being
	// absurd rather than by being short.
	const day = 24 * 60 * 60
	if cert.ValidBefore < cert.ValidAfter || cert.ValidBefore-cert.ValidAfter < day {
		t.Fatalf("the certificate lasts %d seconds — an outage would take SSH with it",
			cert.ValidBefore-cert.ValidAfter)
	}
}

// TestPrincipalsComeFromTheDirectoryAndNotTheRequest.
//
// The attack this endpoint is built against. A compromised machine asking for a
// certificate naming somebody else's service must get its own name back and
// nothing more — and it must not be refused either, because a refusal would tell
// the attacker the field is read at all.
func TestPrincipalsComeFromTheDirectoryAndNotTheRequest(t *testing.T) {
	tryCardinalCLI(t, "host", "create", "e2e-cert-payments")
	host := enrolledHost(t, "e2e-cert-02")

	_, publicKey := hostKeyRequest(t)
	body, err := json.Marshal(map[string]any{
		"publicKey": string(ssh.MarshalAuthorizedKey(publicKey)),
		// Everything a hopeful client might try.
		"principals": []string{"e2e-cert-payments", "*"},
		"hostname":   "e2e-cert-payments",
		"name":       "e2e-cert-payments",
	})
	if err != nil {
		t.Fatal(err)
	}

	status, out := requestCertificate(t, host, body)
	if status != http.StatusOK {
		t.Fatalf("got %d (%s), want 200", status, out.Error)
	}

	cert := parseCertificate(t, out.Certificate)
	if slices.Contains(cert.ValidPrincipals, "e2e-cert-payments") {
		t.Fatalf("a host was given a certificate for another machine's name: %v",
			cert.ValidPrincipals)
	}
	if slices.Contains(cert.ValidPrincipals, "*") {
		t.Fatalf("a wildcard principal was issued: %v", cert.ValidPrincipals)
	}
	if !slices.Contains(cert.ValidPrincipals, "e2e-cert-02") {
		t.Fatalf("the host did not get its own name: %v", cert.ValidPrincipals)
	}
}

// TestAliasesAppearInTheCertificate.
//
// The reason aliases exist: a machine whose directory name is not what anybody
// types needs to prove the name they do type, and it has to be written down
// rather than derived.
func TestAliasesAppearInTheCertificate(t *testing.T) {
	tryCardinalCLI(t, "host", "create", "e2e-cert-03")
	tryCardinalCLI(t, "host", "alias", "add", "e2e-cert-03", "e2e-git.example")
	host := enrolledHost(t, "e2e-cert-03")

	body, _ := hostKeyRequest(t)
	status, out := requestCertificate(t, host, body)
	if status != http.StatusOK {
		t.Fatalf("got %d (%s), want 200", status, out.Error)
	}

	cert := parseCertificate(t, out.Certificate)
	for _, want := range []string{"e2e-cert-03", "e2e-git.example"} {
		if !slices.Contains(cert.ValidPrincipals, want) {
			t.Fatalf("%q is missing from %v", want, cert.ValidPrincipals)
		}
	}
}

// TestAnUnauthenticatedRequestGetsNothing.
func TestAnUnauthenticatedRequestGetsNothing(t *testing.T) {
	body, _ := hostKeyRequest(t)

	req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
		"http://"+hostCardinal+"/api/hosts/certificate", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 — anybody could mint a host certificate",
			resp.StatusCode)
	}
}
