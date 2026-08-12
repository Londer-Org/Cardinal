package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Signing in when the browser is somewhere else.
//
// The loopback flow needs the browser and the CLI to share a loopback
// interface. This one needs neither: the terminal asks first, prints a short
// code, and waits while somebody approves it from whatever has a browser — a
// laptop, a phone, the machine they are SSH'd in from.
//
// What it gives up is the loopback flow's best property. There, approval is
// delivered to the machine that asked, so nobody can talk you into approving
// their terminal. Here they can, and that is the known weakness of the shape.
// The mitigations are the short window, and an approval screen that shows the
// address the request came from as the server saw it — never a name the
// terminal chose.

type deviceStart struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

type deviceCollect struct {
	Status      string `json:"status"`
	Interval    int    `json:"interval"`
	Token       string `json:"token"`
	DeviceBound bool   `json:"deviceBound"`
}

// Device runs the flow and returns the session.
func Device(ctx context.Context, c *http.Client, base string) (*Session, error) {
	verifier, err := RandomString()
	if err != nil {
		return nil, err
	}

	var start deviceStart
	if err := PostJSON(ctx, c, base+"/api/cli/device", "",
		map[string]string{"verifierHash": VerifierHash(verifier)}, &start); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "\n  Approve this terminal from any device with a browser:\n\n")
	fmt.Fprintf(os.Stderr, "    %s\n", start.VerificationURI)
	fmt.Fprintf(os.Stderr, "    code: %s\n\n", start.UserCode)
	fmt.Fprintf(os.Stderr, "  Only approve a code you are looking at right now. Anybody who can\n")
	fmt.Fprintf(os.Stderr, "  get you to approve one is signing *their* terminal in as you.\n\n")
	fmt.Fprintf(os.Stderr, "  waiting")

	interval := time.Duration(start.Interval) * time.Second
	if interval <= 0 {
		interval = 3 * time.Second
	}
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr)
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr)
			return nil, errors.New(
				"nobody approved the terminal in time — run the command again to " +
					"get a new code")
		}

		var out deviceCollect
		err := PostJSON(ctx, c, base+"/api/cli/device/collect", "",
			map[string]string{"deviceCode": start.DeviceCode, "verifier": verifier}, &out)
		if err != nil {
			fmt.Fprintln(os.Stderr)
			return nil, err
		}
		if out.Status == "pending" {
			fmt.Fprint(os.Stderr, ".")
			// The server decides the pace, so it can slow a fleet of these down
			// without shipping a new CLI.
			if out.Interval > 0 {
				interval = time.Duration(out.Interval) * time.Second
			}
			continue
		}

		fmt.Fprintln(os.Stderr)
		var me struct {
			Login string `json:"login"`
		}
		if err := GetJSON(ctx, c, base+"/api/auth/me", out.Token, &me); err != nil {
			return nil, err
		}
		return &Session{
			Token:       out.Token,
			Login:       me.Login,
			DeviceBound: out.DeviceBound,
			ExpiresAt:   time.Now().Add(sessionFloor),
		}, nil
	}
}
