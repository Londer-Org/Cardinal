// Package machine is the machine's half of host authentication.
//
// It lives here rather than in the CLI because it has two callers with the same
// requirements: `cardinal host join`, which an operator runs at a console, and
// cardinal-agent, which runs unattended forever afterwards. Writing the
// signing rules twice is how the two would eventually disagree about what gets
// signed, and a disagreement there is an outage on every host at once.
package machine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"go.londer.be/cardinal/internal/version"
)

// DefaultKeyPath is where a host keeps the key it authenticates with.
//
// Under /etc rather than /var: it is configuration of the machine's identity,
// it must survive whatever /var gets cleaned by, and it must be readable before
// anything else starts. Deliberately not the machine's SSH host key — that key
// already has a job, is rotated on schedules Cardinal does not control, and is
// presented to every stranger who connects to port 22.
const DefaultKeyPath = "/etc/cardinal/host_key"

// Identity is a host's key and what it authenticates as.
type Identity struct {
	Server string
	Signer ssh.Signer
}

// Fingerprint is the identity the server knows this key by.
func (i *Identity) Fingerprint() string {
	return ssh.FingerprintSHA256(i.Signer.PublicKey())
}

// GenerateKey creates a host key and writes it where only root can read it.
//
// Ed25519 unconditionally: it is what the SSH CA already uses, the keys are
// small, and there is no parameter to get wrong. The private half never leaves
// this function's caller — Cardinal is sent the public key and nothing else.
func GenerateKey(path string) (ssh.Signer, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hostclient: generating host key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(private, "cardinal host key")
	if err != nil {
		return nil, fmt.Errorf("hostclient: encoding host key: %w", err)
	}

	if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o700); mkdirErr != nil {
		return nil, fmt.Errorf("hostclient: creating key directory: %w", mkdirErr)
	}

	// O_EXCL, so enrolling twice cannot silently overwrite the key the machine
	// is currently authenticating with and leave it unable to talk to Cardinal
	// until someone re-enrols it by hand.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the path is ours or the operator's
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf(
				"hostclient: %s already exists — this host has a key already; "+
					"remove it deliberately if you mean to replace it", path)
		}
		return nil, fmt.Errorf("hostclient: creating host key file: %w", err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // best effort; the meaningful error is the one being returned

	if encodeErr := pem.Encode(f, block); encodeErr != nil {
		return nil, fmt.Errorf("hostclient: writing host key: %w", encodeErr)
	}

	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, fmt.Errorf("hostclient: loading generated key: %w", err)
	}
	return signer, nil
}

// LoadKey reads the key written by GenerateKey.
func LoadKey(path string) (ssh.Signer, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is ours or the operator's
	if err != nil {
		return nil, fmt.Errorf("hostclient: reading %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("hostclient: parsing %s: %w", path, err)
	}
	return signer, nil
}

// Enroll redeems a token, registering this host's public key.
//
// A nil client means the default one. Enrolling happens once, at a console, and
// making the caller construct an http.Client to do it is friction with no
// upside.
func Enroll(ctx context.Context, client *http.Client, server, token string, public ssh.PublicKey) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	body, err := json.Marshal(map[string]string{
		"token":     token,
		"publicKey": string(ssh.MarshalAuthorizedKey(public)),
	})
	if err != nil {
		return "", fmt.Errorf("hostclient: encoding enrollment: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(server, "/")+"/api/hosts/enroll", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("hostclient: building enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("hostclient: reaching %s: %w", server, err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hostclient: enrollment refused: %s", readError(resp))
	}

	var out struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("hostclient: reading enrollment response: %w", err)
	}
	return out.Host, nil
}

// Sign attaches this host's proof of possession to a request.
//
// Must be called after the request's method and URL are final, because both are
// signed: a signature made before a redirect or a path rewrite would not verify
// against the request that actually gets sent.
func (i *Identity) Sign(req *http.Request) error {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	fingerprint := i.Fingerprint()

	signature, err := i.Signer.Sign(rand.Reader, signingString(
		req.Method, req.URL.Path, timestamp, fingerprint))
	if err != nil {
		return fmt.Errorf("hostclient: signing request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Cardinal-Host %s:%s:%s",
		fingerprint, timestamp,
		base64.StdEncoding.EncodeToString(ssh.Marshal(signature))))
	return nil
}

// Do sends a signed request.
func (i *Identity) Do(ctx context.Context, client *http.Client, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method,
		strings.TrimRight(i.Server, "/")+path, body)
	if err != nil {
		return nil, fmt.Errorf("hostclient: building request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// So the server can say, in its own log, that a host is running something
	// newer than it. Without it the only symptom of that mismatch is a 404 the
	// agent reports as a fetch failure while it goes on serving its cache.
	req.Header.Set("User-Agent", version.AgentUserAgent)
	if err := i.Sign(req); err != nil {
		return nil, err
	}
	return client.Do(req)
}

// signingString mirrors the server's reconstruction of it exactly.
//
// The two are separate implementations on purpose — the server must never trust
// a client-supplied string — but they are one specification, restated in the
// comment on internal/httpapi/hostauth.go. Change one and the tests that talk
// to a real server fail immediately, which is the point.
func signingString(method, path, timestamp, fingerprint string) []byte {
	return []byte(strings.Join([]string{
		"cardinal-host-v1", method, path, timestamp, fingerprint,
	}, "\n"))
}

func readError(resp *http.Response) string {
	var out struct {
		Error string `json:"error"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err == nil && json.Unmarshal(raw, &out) == nil && out.Error != "" {
		return out.Error
	}
	return resp.Status
}
