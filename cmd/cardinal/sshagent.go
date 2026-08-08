package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Handing the certificate to ssh-agent.
//
// The agent rather than a file, and that is the point of the whole arrangement.
// A certificate written to ~/.ssh outlives the session that fetched it and has
// to be cleaned up by something; one added to the agent with a lifetime expires
// on its own, and a laptop that sleeps for an hour wakes up holding nothing.
//
// The lifetime comes from the certificate, not from a number chosen here. Two
// expiries for one credential drift, and the one that matters is the one the
// authority signed.
func addToAgent(ctx context.Context, priv ed25519.PrivateKey, cert *ssh.Certificate, expires time.Time) error {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return errors.New(
			"no ssh-agent is running (SSH_AUTH_SOCK is unset), so there is nowhere " +
				"to put the certificate.\n\n" +
				"  Start one with `eval $(ssh-agent)`, or use -print to see the " +
				"certificate without connecting")
	}

	// G704 reads SSH_AUTH_SOCK as tainted input. It is: it is the address of
	// the agent this session already trusts with every key it holds, and a
	// process that can rewrite it can read the environment it came from anyway.
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("reaching ssh-agent at %s: %w", socket, err)
	}
	defer conn.Close() //nolint:errcheck // best effort; the meaningful error is the one being returned

	// Seconds remaining, rounded down, and at least one. A zero LifetimeSecs
	// means "forever" to the agent protocol — precisely the opposite of what an
	// expiring certificate is for, and what a naive truncation produces in the
	// last second of validity.
	remaining := time.Until(expires)
	if remaining <= 0 {
		return errors.New("the certificate Cardinal issued has already expired")
	}
	lifetime := uint32(remaining.Seconds())
	if lifetime == 0 {
		lifetime = 1
	}

	if err := agent.NewClient(conn).Add(agent.AddedKey{
		PrivateKey:   priv,
		Certificate:  cert,
		Comment:      fmt.Sprintf("cardinal %s (expires %s)", cert.KeyId, expires.Format(time.Kitchen)),
		LifetimeSecs: lifetime,
	}); err != nil {
		return fmt.Errorf("adding the certificate to ssh-agent: %w", err)
	}
	return nil
}
