package agent_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.londer.be/cardinal/internal/agent"
	"go.londer.be/cardinal/internal/sshca"
	"golang.org/x/crypto/ssh"
)

func keypair(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer, signer.PublicKey()
}

// certServer stands in for Cardinal, signing whatever it is sent.
//
// The signing goes through sshca so the agent is checking a certificate the
// server would really produce — a hand-built one could omit something the real
// path includes and the check would pass anyway.
func certServer(t *testing.T, principals []string, tamper func(*ssh.Certificate)) *httptest.Server {
	t.Helper()
	caSigner, _ := keypair(t)

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				PublicKey string `json:"publicKey"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				return
			}
			publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
			if err != nil {
				t.Error(err)
				return
			}

			cert, err := sshca.SignHostCertificate(caSigner, sshca.HostRequest{
				Name: "web-01.prod", PublicKey: publicKey, Principals: principals,
			})
			if err != nil {
				t.Error(err)
				return
			}
			if tamper != nil {
				tamper(cert)
				if err := cert.SignCert(rand.Reader, caSigner); err != nil {
					t.Error(err)
					return
				}
			}

			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // the header is already written, so the status cannot be changed
				"certificate": string(ssh.MarshalAuthorizedKey(cert)),
				"principals":  cert.ValidPrincipals,
			})
		}))
}

func hostKeyOnDisk(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	_, public := keypair(t)
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key.pub"),
		ssh.MarshalAuthorizedKey(public), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestCertificateIsFetchedAndInstalled.
func TestCertificateIsFetchedAndInstalled(t *testing.T) {
	dir := hostKeyOnDisk(t)
	server := certServer(t, []string{"web-01.prod"}, nil)
	defer server.Close()

	a := &agent.Agent{
		Identity:       testIdentity(t, server.URL),
		HostKeyPath:    filepath.Join(dir, "ssh_host_ed25519_key.pub"),
		HostCertPath:   filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"),
		SSHDDropInPath: filepath.Join(dir, "sshd_config.d", "50-cardinal.conf"),
	}

	changed, err := a.RefreshHostCertificate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("a host with no certificate did not get one")
	}

	installed, err := agent.ReadHostCertificate(a.HostCertPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(installed.Principals) != 1 || installed.Principals[0] != "web-01.prod" {
		t.Fatalf("wrong principals: %v", installed.Principals)
	}

	// The drop-in has to exist too. A certificate sshd is not told to present is
	// the failure that looks exactly like success.
	if _, err := os.Stat(a.SSHDDropInPath); err != nil {
		t.Fatalf("the sshd drop-in was not written: %v", err)
	}
}

// TestAValidCertificateIsNotReplaced.
//
// Renewal is a third of the way from expiry, so a fresh certificate is left
// alone. Without this the agent would request a new one every five minutes and
// fill the journal with issuances nobody made a decision about.
func TestAValidCertificateIsNotReplaced(t *testing.T) {
	dir := hostKeyOnDisk(t)
	var requests int
	upstream := certServer(t, []string{"web-01.prod"}, nil)
	defer upstream.Close()

	counted := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requests++
			http.Redirect(w, r, upstream.URL+r.URL.Path, http.StatusTemporaryRedirect)
		}))
	defer counted.Close()

	a := &agent.Agent{
		Identity:       testIdentity(t, counted.URL),
		HostKeyPath:    filepath.Join(dir, "ssh_host_ed25519_key.pub"),
		HostCertPath:   filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"),
		SSHDDropInPath: filepath.Join(dir, "sshd_config.d", "50-cardinal.conf"),
	}

	if _, err := a.RefreshHostCertificate(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := requests

	changed, err := a.RefreshHostCertificate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("a certificate with its whole life ahead of it was replaced")
	}
	if requests != first {
		t.Fatalf("the agent asked again: %d requests, want %d", requests, first)
	}
}

// TestRenewalTiming.
//
// The threshold is the outage budget: a seven-day certificate renewed with a
// third of its life left means Cardinal can be unreachable for two days before
// anybody sees a prompt.
func TestRenewalTiming(t *testing.T) {
	const life = 7 * 24 * time.Hour

	for _, tc := range []struct {
		name      string
		remaining time.Duration
		want      bool
	}{
		{"brand new", life, false},
		{"half gone", life / 2, false},
		{"just past the threshold", life/3 - time.Minute, true},
		{"nearly expired", time.Hour, true},
		{"expired", -time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &agent.HostCertificate{ValidUntil: time.Now().Add(tc.remaining)}
			if got := cert.NeedsRenewal(life); got != tc.want {
				t.Fatalf("got %v, want %v with %s remaining", got, tc.want, tc.remaining)
			}
		})
	}

	// Nothing installed is always due, and it must not panic on the nil.
	var absent *agent.HostCertificate
	if !absent.NeedsRenewal(life) {
		t.Fatal("a host with no certificate must be due for one")
	}
}

// TestACertificateForAnotherKeyIsRefused.
//
// The failure this check exists for is quiet: sshd starts, offers a certificate
// for a key it does not hold, every client falls back to a fingerprint prompt,
// and the agent reports success the whole time.
func TestACertificateForAnotherKeyIsRefused(t *testing.T) {
	dir := hostKeyOnDisk(t)

	// The server signs whatever it is sent — so to produce a mismatch, the
	// agent is pointed at a *different* key than the one it will present.
	_, other := keypair(t)
	otherPath := filepath.Join(dir, "someone-elses-key.pub")
	if err := os.WriteFile(otherPath, ssh.MarshalAuthorizedKey(other), 0o600); err != nil {
		t.Fatal(err)
	}

	server := certServer(t, []string{"web-01.prod"}, func(c *ssh.Certificate) {
		_, replacement := keypair(t)
		c.Key = replacement
	})
	defer server.Close()

	a := &agent.Agent{
		Identity:     testIdentity(t, server.URL),
		HostKeyPath:  filepath.Join(dir, "ssh_host_ed25519_key.pub"),
		HostCertPath: filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"),
	}

	if _, err := a.RefreshHostCertificate(t.Context()); err == nil {
		t.Fatal("a certificate for a different key was installed")
	}
	if _, err := os.Stat(a.HostCertPath); err == nil {
		t.Fatal("the rejected certificate was written to disk anyway")
	}
}

// TestACertificateWithNoPrincipalsIsRefused.
//
// OpenSSH reads an empty principal list on a host certificate as valid for
// *every* hostname. Checked here as well as at the signer, because this is the
// last place it can be caught before it is trusted.
func TestACertificateWithNoPrincipalsIsRefused(t *testing.T) {
	dir := hostKeyOnDisk(t)

	server := certServer(t, []string{"web-01.prod"}, func(c *ssh.Certificate) {
		c.ValidPrincipals = nil
	})
	defer server.Close()

	a := &agent.Agent{
		Identity:     testIdentity(t, server.URL),
		HostKeyPath:  filepath.Join(dir, "ssh_host_ed25519_key.pub"),
		HostCertPath: filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"),
	}

	if _, err := a.RefreshHostCertificate(t.Context()); err == nil {
		t.Fatal("a certificate matching every hostname was installed")
	}
}

// TestAUserCertificateIsRefused.
//
// sshd refuses to start with one installed as HostCertificate, and the moment
// that is discovered is the next reboot — by which time nobody can log in.
func TestAUserCertificateIsRefused(t *testing.T) {
	dir := hostKeyOnDisk(t)

	server := certServer(t, []string{"web-01.prod"}, func(c *ssh.Certificate) {
		c.CertType = ssh.UserCert
	})
	defer server.Close()

	a := &agent.Agent{
		Identity:     testIdentity(t, server.URL),
		HostKeyPath:  filepath.Join(dir, "ssh_host_ed25519_key.pub"),
		HostCertPath: filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"),
	}

	if _, err := a.RefreshHostCertificate(t.Context()); err == nil {
		t.Fatal("a user certificate was installed where sshd expects a host one")
	}
}

// TestAnUnreadableCertificateIsReplacedRatherThanKept.
//
// Whatever it is, it is not doing its job, and sshd will not start with it in
// place — so the useful response is to get a new one rather than to preserve it.
func TestAnUnreadableCertificateIsReplacedRatherThanKept(t *testing.T) {
	dir := hostKeyOnDisk(t)
	certPath := filepath.Join(dir, "ssh_host_ed25519_key-cert.pub")
	if err := os.WriteFile(certPath, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	server := certServer(t, []string{"web-01.prod"}, nil)
	defer server.Close()

	a := &agent.Agent{
		Identity:     testIdentity(t, server.URL),
		HostKeyPath:  filepath.Join(dir, "ssh_host_ed25519_key.pub"),
		HostCertPath: certPath,
	}

	changed, err := a.RefreshHostCertificate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("an unreadable certificate was left in place")
	}
	if _, err := agent.ReadHostCertificate(certPath); err != nil {
		t.Fatalf("the replacement is not readable either: %v", err)
	}
}

// TestHostCertificateRenewalIsOffByDefault.
//
// An agent with no host key configured must not reach for /etc/ssh. Every test
// above sets the paths explicitly for exactly this reason.
func TestHostCertificateRenewalIsOffByDefault(t *testing.T) {
	a := &agent.Agent{Identity: testIdentity(t, "http://127.0.0.1:1")}

	changed, err := a.RefreshHostCertificate(t.Context())
	if err != nil {
		t.Fatalf("an agent with no host key configured tried to do something: %v", err)
	}
	if changed {
		t.Fatal("something was installed with no host key configured")
	}
}
