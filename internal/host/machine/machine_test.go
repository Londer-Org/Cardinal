package machine_test

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/host/machine"
	"golang.org/x/crypto/ssh"
)

// TestGeneratedKeyIsNotReadableByOtherUsers.
//
// This is the credential the machine authenticates to Cardinal with. Anything
// that can read it can impersonate the host — fetch its assignment, obtain its
// certificate, and be told which people may log in. A mode this test does not
// hold to is one that a future refactor can loosen invisibly.
func TestGeneratedKeyIsNotReadableByOtherUsers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "host_key")

	_, err := machine.GenerateKey(path)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"the host private key must not be readable by group or other")

	parent, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), parent.Mode().Perm(),
		"a traversable directory would let the key be reached even at 0600")
}

// TestGenerateKeyRefusesToOverwrite: enrolling twice must not silently replace
// the key the machine is currently authenticating with, which would leave it
// unable to talk to Cardinal until somebody re-enrolled it by hand.
func TestGenerateKeyRefusesToOverwrite(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "host_key")

	first, err := machine.GenerateKey(path)
	require.NoError(t, err)

	_, err = machine.GenerateKey(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists",
		"the message has to tell the operator what to do about it")

	// And the original key is untouched, which is the property that matters
	// more than the error.
	reloaded, err := machine.LoadKey(path)
	require.NoError(t, err)
	assert.Equal(t, first.PublicKey().Marshal(), reloaded.PublicKey().Marshal(),
		"the failed second call must not have replaced the key")
}

func TestGeneratedKeyRoundTripsThroughLoadKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "host_key")

	generated, err := machine.GenerateKey(path)
	require.NoError(t, err)

	loaded, err := machine.LoadKey(path)
	require.NoError(t, err)

	assert.Equal(t, generated.PublicKey().Marshal(), loaded.PublicKey().Marshal())
	assert.Equal(t, "ssh-ed25519", loaded.PublicKey().Type(),
		"ed25519 by choice; a change of algorithm is a change of what the server must accept")
}

func TestLoadKeyReportsThePathItCouldNotRead(t *testing.T) {
	t.Parallel()

	_, err := machine.LoadKey(filepath.Join(t.TempDir(), "absent"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absent",
		"an agent that cannot start should say which file it wanted")
}

// signedIdentity is a host identity backed by a throwaway key.
func signedIdentity(t *testing.T) (*machine.Identity, ssh.PublicKey) {
	t.Helper()

	signer, err := machine.GenerateKey(filepath.Join(t.TempDir(), "host_key"))
	require.NoError(t, err)

	return &machine.Identity{Server: "https://id.cardinal.test", Signer: signer},
		signer.PublicKey()
}

// TestSignatureCoversMethodPathAndTimestamp is the replay and substitution
// property.
//
// The server reconstructs the signing string from what it received, so anything
// outside that string is unauthenticated. Verifying the signature here against
// the same fields — and then against altered ones — is what shows the binding
// is real rather than decorative.
func TestSignatureCoversMethodPathAndTimestamp(t *testing.T) {
	t.Parallel()

	identity, public := signedIdentity(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://id.cardinal.test/api/hosts/me", nil)
	require.NoError(t, err)
	require.NoError(t, identity.Sign(req))

	fingerprint, timestamp, signature := parseAuthorization(t, req)
	assert.Equal(t, identity.Fingerprint(), fingerprint)

	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), time.Unix(seconds, 0), time.Minute,
		"the timestamp is what bounds a replay, so it must be the current one")

	signed := func(method, path, ts string) []byte {
		return []byte(strings.Join([]string{
			"cardinal-host-v1", method, path, ts, fingerprint,
		}, "\n"))
	}

	require.NoError(t,
		public.Verify(signed(http.MethodGet, "/api/hosts/me", timestamp), signature),
		"the signature must verify over exactly the string the server rebuilds")

	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"a different method", signed(http.MethodDelete, "/api/hosts/me", timestamp)},
		{"a different path", signed(http.MethodGet, "/api/hosts/assignment", timestamp)},
		{"a different timestamp", signed(http.MethodGet, "/api/hosts/me", "1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, public.Verify(tc.payload, signature),
				"%s must not verify, or it is not covered by the signature", tc.name)
		})
	}
}

func TestFingerprintIsTheKeysOwn(t *testing.T) {
	t.Parallel()

	identity, public := signedIdentity(t)
	assert.Equal(t, ssh.FingerprintSHA256(public), identity.Fingerprint(),
		"the server looks the host up by this, so it must be the standard form")
}

// parseAuthorization splits the header Sign writes.
func parseAuthorization(t *testing.T, req *http.Request) (fingerprint, timestamp string, signature *ssh.Signature) {
	t.Helper()

	header := req.Header.Get("Authorization")
	scheme, rest, found := strings.Cut(header, " ")
	require.True(t, found, "Authorization header is %q", header)
	require.Equal(t, "Cardinal-Host", scheme)

	// From the right, deliberately. The value is fingerprint:timestamp:signature
	// and an SSH SHA256 fingerprint is itself "SHA256:<base64>" — so splitting
	// on the first two colons takes the fingerprint apart and hands the caller a
	// timestamp that is really the second half of it. The server's parser has
	// the same problem to solve.
	head, encoded, found := cutLast(rest, ":")
	require.True(t, found, "expected fingerprint:timestamp:signature, got %q", rest)
	fingerprint, timestamp, found = cutLast(head, ":")
	require.True(t, found, "expected a timestamp before the signature, got %q", head)

	raw, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)

	signature = new(ssh.Signature)
	require.NoError(t, ssh.Unmarshal(raw, signature))
	return fingerprint, timestamp, signature
}

// cutLast is strings.Cut around the final separator rather than the first.
func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}
