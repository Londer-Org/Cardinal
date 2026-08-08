package httpapi

import (
	"net/http"
	"testing"
)

func request(remoteAddr string, forwarded ...string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	for _, f := range forwarded {
		r.Header.Add("X-Forwarded-For", f)
	}
	return r
}

// TestUntrustedPeerHeadersIgnored is the property that matters most.
//
// Without it, anyone can evade rate limiting by varying a header — and rate
// limiting is what bounds online guessing against authentication endpoints.
func TestUntrustedPeerHeadersIgnored(t *testing.T) {
	r, err := newClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}

	// A direct connection from an arbitrary address, claiming to be someone
	// else. The claim must count for nothing.
	got := r.resolve(request("203.0.113.9:5555", "1.2.3.4"))
	if got != "203.0.113.9" {
		t.Fatalf("header from an untrusted peer was honoured: got %q", got)
	}
}

func TestNoTrustedProxiesConfigured(t *testing.T) {
	r, err := newClientIPResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Default posture: trust nothing, so a deployment that forgets to configure
	// proxies is safe rather than open.
	if got := r.resolve(request("10.0.0.5:1234", "1.2.3.4")); got != "10.0.0.5" {
		t.Fatalf("got %q, want the peer address", got)
	}
}

// TestRightmostUntrustedHopWins encodes the algorithm most implementations get
// wrong.
//
// A client can send its own X-Forwarded-For, and the proxy *appends* rather
// than replacing. So the left of the list is attacker-written and the right is
// proxy-written. Reading left-to-right hands the attacker control.
func TestRightmostUntrustedHopWins(t *testing.T) {
	r, err := newClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}

	// The client forged "1.2.3.4"; the proxy then appended the real peer.
	got := r.resolve(request("10.0.0.1:443", "1.2.3.4, 203.0.113.9"))
	if got != "203.0.113.9" {
		t.Fatalf("forged leftmost entry was trusted: got %q, want 203.0.113.9", got)
	}
}

func TestChainedTrustedProxiesAreSkipped(t *testing.T) {
	r, err := newClientIPResolver([]string{"10.0.0.0/8", "172.16.0.0/12"})
	if err != nil {
		t.Fatal(err)
	}

	// Real client, then two internal hops, both trusted.
	got := r.resolve(request("10.0.0.1:443", "203.0.113.9, 172.16.0.4, 10.0.0.2"))
	if got != "203.0.113.9" {
		t.Fatalf("got %q, want the first untrusted hop", got)
	}
}

func TestRepeatedHeadersAreFlattenedInOrder(t *testing.T) {
	r, err := newClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	got := r.resolve(request("10.0.0.1:443", "203.0.113.9", "10.0.0.2"))
	if got != "203.0.113.9" {
		t.Fatalf("got %q, want 203.0.113.9", got)
	}
}

// TestMalformedHopStopsTheWalk: a chain containing garbage cannot be reasoned
// about past that point, so stop rather than guessing.
func TestMalformedHopStopsTheWalk(t *testing.T) {
	r, err := newClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	got := r.resolve(request("10.0.0.1:443", "203.0.113.9, not-an-ip, 10.0.0.2"))
	if got != "10.0.0.1" {
		t.Fatalf("got %q — a malformed chain must fall back to the peer", got)
	}
}

// TestAllHopsTrusted: if every entry is a proxy, the original client is simply
// not identifiable. Inventing an answer would be worse than admitting it.
func TestAllHopsTrusted(t *testing.T) {
	r, err := newClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	got := r.resolve(request("10.0.0.1:443", "10.0.0.2, 10.0.0.3"))
	if got != "10.0.0.1" {
		t.Fatalf("got %q, want the peer address", got)
	}
}

// TestIPv4MappedIPv6Normalised: a proxy reaching us over IPv6 may present the
// peer as ::ffff:10.0.0.1. Without normalisation it would not match a v4 CIDR
// and the proxy would silently stop being trusted.
func TestIPv4MappedIPv6Normalised(t *testing.T) {
	r, err := newClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	got := r.resolve(request("[::ffff:10.0.0.1]:443", "203.0.113.9"))
	if got != "203.0.113.9" {
		t.Fatalf("got %q — v4-mapped v6 peer should have been recognised as trusted", got)
	}
}

func TestBareAddressAcceptedAsPrefix(t *testing.T) {
	r, err := newClientIPResolver([]string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("a bare address should be accepted as a /32: %v", err)
	}
	if got := r.resolve(request("10.0.0.1:443", "203.0.113.9")); got != "203.0.113.9" {
		t.Fatalf("got %q", got)
	}
	if got := r.resolve(request("10.0.0.2:443", "203.0.113.9")); got != "10.0.0.2" {
		t.Fatalf("got %q — 10.0.0.2 is outside the /32 and must not be trusted", got)
	}
}

func TestInvalidCIDRRejected(t *testing.T) {
	if _, err := newClientIPResolver([]string{"not-a-cidr"}); err == nil {
		t.Fatal("an invalid trusted_proxies entry must fail at startup, not silently")
	}
}
