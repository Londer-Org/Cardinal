package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// clientIPResolver determines the address to attribute a request to.
//
// This feeds rate limiting and audit, so getting it wrong has consequences in
// both directions: trust the header when you shouldn't and anyone evades rate
// limiting by varying it; ignore it when you should trust it and every request
// appears to come from the proxy, so one abusive client exhausts the allowance
// for everybody.
type clientIPResolver struct {
	trusted []netip.Prefix
}

func newClientIPResolver(cidrs []string) (*clientIPResolver, error) {
	r := &clientIPResolver{}
	for _, raw := range cidrs {
		prefix, err := parsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, err
		}
		r.trusted = append(r.trusted, prefix)
	}
	return r, nil
}

// parsePrefix accepts a CIDR or a bare address, since operators reasonably
// write either.
func parsePrefix(s string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// resolve returns the address to attribute the request to.
//
// The algorithm is the one that actually holds up:
//
//  1. If the immediate peer is not a trusted proxy, use the peer address and
//     ignore every forwarding header. Anyone can set X-Forwarded-For; only the
//     TCP peer address cannot be forged.
//
//  2. If the peer *is* trusted, walk X-Forwarded-For from the RIGHT, skipping
//     trusted proxies, and take the first untrusted address. That is the
//     furthest hop we have reason to believe.
//
// Taking the leftmost entry — which is what most naive implementations do — is
// exactly wrong: the left of the list is the part a client can write freely.
// A request arriving with "X-Forwarded-For: 1.2.3.4" gets that value prepended
// to, not replaced by, the proxy's own append.
func (r *clientIPResolver) resolve(req *http.Request) string {
	peer := peerAddr(req)

	// No trusted proxies configured, or the peer is not one of them: the
	// connection address is the only thing we know to be true.
	if len(r.trusted) == 0 || !r.isTrusted(peer) {
		return peer.String()
	}

	forwarded := req.Header.Values("X-Forwarded-For")
	if len(forwarded) == 0 {
		return peer.String()
	}

	// Headers may be repeated and comma-separated; flatten in order.
	var hops []string
	for _, header := range forwarded {
		hops = append(hops, strings.Split(header, ",")...)
	}

	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			// A malformed hop means the chain cannot be trusted beyond this
			// point. Stop rather than guessing.
			break
		}
		if !r.isTrusted(addr) {
			return addr.String()
		}
	}

	// Every hop was a trusted proxy, so the original client is not identifiable
	// from the chain. Attribute to the peer rather than inventing an answer.
	return peer.String()
}

func (r *clientIPResolver) isTrusted(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	// Normalise v4-in-v6 so 192.0.2.1 and ::ffff:192.0.2.1 compare equal.
	addr = addr.Unmap()
	for _, prefix := range r.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func peerAddr(req *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}
