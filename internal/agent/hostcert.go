package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Where a host keeps its own key and the certificate for it.
//
// Ed25519 only. It is what the authority signs with, what every OpenSSH since
// 6.5 supports, and picking one avoids the question of what to do when a machine
// has four host keys and Cardinal has signed two of them.
const (
	DefaultHostKeyPath  = "/etc/ssh/ssh_host_ed25519_key.pub"
	DefaultHostCertPath = "/etc/ssh/ssh_host_ed25519_key-cert.pub"

	// DefaultSSHDDropIn is where the HostCertificate directive goes.
	//
	// A drop-in rather than an edit to sshd_config, for the same reason the
	// sudoers file is a drop-in: the agent must not be able to change how a
	// machine authenticates people, only to add a fact about itself. Every
	// current distribution ships `Include /etc/ssh/sshd_config.d/*.conf`.
	DefaultSSHDDropIn = "/etc/ssh/sshd_config.d/50-cardinal.conf"
)

// renewAt is the fraction of a certificate's life at which to replace it.
//
// A third remaining, so a seven-day certificate is renewed with two days to
// spare. That is the outage budget: Cardinal can be unreachable for two days
// after the last renewal before anybody sees a TOFU prompt, and unreachable for
// seven before the certificate is gone entirely.
const renewAt = 3

// HostCertificate is what the agent knows about its own certificate.
type HostCertificate struct {
	Principals []string
	ValidUntil time.Time
	Serial     uint64
}

// NeedsRenewal reports whether it is time to ask for a new one.
//
// Based on what is on disk rather than on when the agent last asked, so a
// restarted agent does not re-request immediately and a machine that has been
// off for a week renews as soon as it comes back.
func (h *HostCertificate) NeedsRenewal(total time.Duration) bool {
	if h == nil {
		return true
	}
	return time.Until(h.ValidUntil) < total/renewAt
}

// ReadHostCertificate parses the certificate currently installed.
func ReadHostCertificate(path string) (*HostCertificate, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is ours or the operator's
	if err != nil {
		return nil, err
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return nil, fmt.Errorf("agent: %s is not a certificate: %w", path, err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("agent: %s is a public key, not a certificate", path)
	}
	if cert.CertType != ssh.HostCert {
		// A user certificate installed as HostCertificate makes sshd refuse to
		// start. Worth catching here rather than by the machine not coming back.
		return nil, fmt.Errorf("agent: %s is a user certificate, not a host one", path)
	}

	return &HostCertificate{
		Principals: cert.ValidPrincipals,
		ValidUntil: time.Unix(int64(cert.ValidBefore), 0), //nolint:gosec // clamped at signing
		Serial:     cert.Serial,
	}, nil
}

// RefreshHostCertificate obtains a certificate and installs it if one is due.
//
// Returns whether anything changed, so the caller can decide about restarting
// sshd — which this package deliberately does not do. Reloading the daemon that
// is currently carrying the operator's session is not a thing to do as a side
// effect of a periodic refresh.
func (a *Agent) RefreshHostCertificate(ctx context.Context) (bool, error) {
	if a.HostKeyPath == "" {
		return false, nil
	}

	existing, err := ReadHostCertificate(a.hostCertPath())
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		existing = nil
	default:
		// A certificate that will not parse is replaced rather than repaired.
		// Whatever it is, it is not doing its job, and sshd will not start with
		// it in place.
		a.log().Warn("the installed host certificate is unreadable and will be replaced",
			"error", err)
		existing = nil
	}

	if !existing.NeedsRenewal(a.hostCertValidity()) {
		return false, nil
	}

	publicKey, err := os.ReadFile(a.HostKeyPath)
	if err != nil {
		return false, fmt.Errorf("agent: reading the host key: %w", err)
	}

	body, err := json.Marshal(map[string]string{"publicKey": string(publicKey)})
	if err != nil {
		return false, fmt.Errorf("agent: encoding the certificate request: %w", err)
	}

	resp, err := a.Identity.Do(ctx, a.client(), http.MethodPost,
		"/api/hosts/certificate", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("agent: requesting a host certificate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("agent: Cardinal refused a host certificate: %s",
			describe(resp))
	}

	var issued struct {
		Certificate string   `json:"certificate"`
		Principals  []string `json:"principals"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&issued); err != nil {
		return false, fmt.Errorf("agent: reading the certificate: %w", err)
	}

	// Parsed before it is written. A certificate that does not parse, or that
	// is not for this key, makes sshd refuse to start — and a machine whose sshd
	// will not start is one somebody has to walk to.
	if err := a.verifyIssued(issued.Certificate, publicKey); err != nil {
		return false, err
	}

	if err := writeFileAtomically(a.hostCertPath(), []byte(issued.Certificate), 0o644); err != nil {
		return false, err
	}

	if err := a.writeSSHDDropIn(ctx); err != nil {
		return false, err
	}

	a.log().Info("host certificate installed",
		"principals", issued.Principals, "path", a.hostCertPath())
	return true, nil
}

// verifyIssued checks the certificate before it can break sshd.
func (a *Agent) verifyIssued(certificate string, hostKey []byte) error {
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certificate))
	if err != nil {
		return fmt.Errorf("agent: Cardinal returned something that is not a certificate: %w", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return errors.New("agent: Cardinal returned a public key, not a certificate")
	}
	if cert.CertType != ssh.HostCert {
		return errors.New("agent: Cardinal returned a user certificate; sshd would refuse to start")
	}

	// The certificate has to be for the key sshd will present. Otherwise sshd
	// starts, offers a certificate for a key it does not have, and every client
	// falls back to TOFU while the agent reports success.
	expected, _, _, _, err := ssh.ParseAuthorizedKey(hostKey)
	if err != nil {
		return fmt.Errorf("agent: the local host key is unreadable: %w", err)
	}
	if !bytes.Equal(cert.Key.Marshal(), expected.Marshal()) {
		return errors.New("agent: the certificate is for a different key than this host presents")
	}

	if len(cert.ValidPrincipals) == 0 {
		// OpenSSH reads an empty principal list on a host certificate as valid
		// for every hostname. Refused here as well as at the signer, because
		// this is the last place it can be caught before it is trusted.
		return errors.New("agent: the certificate names no principals, so it would match any hostname")
	}
	return nil
}

// writeSSHDDropIn points sshd at the certificate.
//
// A drop-in, validated with `sshd -t` before it is moved into place, and
// sshd_config itself is never touched. The rule is the one the sudoers renderer
// follows: the agent may add a fact about this machine, and may not change how
// the machine authenticates people.
func (a *Agent) writeSSHDDropIn(ctx context.Context) error {
	if a.SSHDDropInPath == "" {
		return nil
	}

	content := fmt.Sprintf(`# Managed by Cardinal. Edits are discarded on the next renewal.
#
# Presents the certificate Cardinal signed, so clients that trust the authority
# verify this machine's name instead of being asked to accept a fingerprint they
# cannot evaluate. On the client side:
#
#   @cert-authority *.example  ssh-ed25519 AAAA...   (in known_hosts)
#
HostCertificate %s
`, a.hostCertPath())

	dir := filepath.Dir(a.SSHDDropInPath)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // sshd's own directory mode
		return fmt.Errorf("agent: creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".cardinal-*.conf")
	if err != nil {
		return fmt.Errorf("agent: creating the sshd drop-in candidate: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: writing the sshd drop-in: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agent: closing the sshd drop-in: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { //nolint:gosec // sshd config is world-readable
		return fmt.Errorf("agent: setting the drop-in permissions: %w", err)
	}

	if err := validateSSHDConfig(ctx, tmp.Name()); err != nil {
		return err
	}

	if err := os.Rename(tmp.Name(), a.SSHDDropInPath); err != nil {
		return fmt.Errorf("agent: installing the sshd drop-in: %w", err)
	}
	return nil
}

// validateSSHDConfig runs `sshd -t` against a candidate.
//
// Same discipline as visudo: an invalid sshd_config stops the daemon starting,
// and the moment that is discovered is the next reboot — by which time nobody
// can log in to fix it.
func validateSSHDConfig(ctx context.Context, path string) error {
	// A drop-in for a daemon that is not installed cannot break anything, so an
	// absent sshd is nothing to refuse over. Written as a lookup rather than as
	// an error branch, because "return nil because something failed" is exactly
	// the shape that hides a real mistake.
	sshd, found := lookSSHD()
	if !found {
		return nil
	}

	// -T rather than -t: -t validates the *system* configuration including the
	// candidate's neighbours, which is what actually matters, but it also needs
	// host keys to exist. -T extends it with "print the effective config", which
	// fails the same way and works in a container.
	//nolint:gosec // sshd comes from LookPath and the path is one we just wrote
	cmd := exec.CommandContext(ctx, sshd, "-T", "-f", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("agent: sshd rejected the drop-in, so it was not installed: %w\n%s",
			err, strings.TrimSpace(string(output)))
	}
	return nil
}

func lookSSHD() (path string, found bool) {
	// Not on PATH for a non-root process on most distributions, where it lives
	// in sbin. Checked explicitly so the agent does not silently skip
	// validation on every machine it actually runs on.
	if resolved, err := exec.LookPath("sshd"); err == nil {
		return resolved, true
	}
	for _, candidate := range []string{"/usr/sbin/sshd", "/sbin/sshd"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
	}
	return "", false
}

func (a *Agent) hostCertPath() string {
	if a.HostCertPath != "" {
		return a.HostCertPath
	}
	return DefaultHostCertPath
}

func (a *Agent) hostCertValidity() time.Duration {
	if a.HostCertValidity > 0 {
		return a.HostCertValidity
	}
	return 7 * 24 * time.Hour
}

// writeFileAtomically is the same temp-sync-rename dance the cache uses.
//
// Worth repeating here rather than sharing, because the failure differs: a
// half-written cache costs a refresh, and a half-written certificate makes sshd
// refuse to start.
func writeFileAtomically(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // /etc/ssh's own mode
		return fmt.Errorf("agent: creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".cardinal-*")
	if err != nil {
		return fmt.Errorf("agent: creating a candidate in %s: %w", dir, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: writing %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: syncing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agent: closing %s: %w", path, err)
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return fmt.Errorf("agent: setting permissions on %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("agent: installing %s: %w", path, err)
	}
	return nil
}
