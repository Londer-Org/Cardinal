package store

import (
	"testing"
	"time"
)

// TestRequiresFreshAuthentication.
//
// The rule an OIDC client relies on when it asks for `prompt=login` or a
// `max_age`. Cardinal used to accept both parameters and act on neither, which
// is not a missing feature but a false answer: a client asking for a fresh
// ceremony before a payment or a privilege change was told the user had
// authenticated when what had actually happened was a session from that
// morning.
//
// Kept as a table test on the pure decision, because the interesting part is
// the boundary rather than the plumbing around it.
func TestRequiresFreshAuthentication(t *testing.T) {
	seconds := func(n int64) *int64 { return &n }
	now := time.Now()

	for _, tc := range []struct {
		name   string
		req    AuthRequest
		authAt time.Time
		want   bool
	}{
		{
			name:   "no constraint accepts an old authentication",
			req:    AuthRequest{},
			authAt: now.Add(-8 * time.Hour),
			want:   false,
		},
		{
			name:   "prompt=login always requires a new one",
			req:    AuthRequest{Prompt: []string{"login"}},
			authAt: now,
			want:   true,
		},
		{
			// The client asked for the ceremony, not for an opinion about
			// whether one looked necessary.
			name:   "prompt=login ignores how recent the session is",
			req:    AuthRequest{Prompt: []string{"login"}},
			authAt: now.Add(-time.Second),
			want:   true,
		},
		{
			name:   "prompt=none alone constrains nothing",
			req:    AuthRequest{Prompt: []string{"none"}},
			authAt: now.Add(-8 * time.Hour),
			want:   false,
		},
		{
			name:   "max_age accepts an authentication inside the window",
			req:    AuthRequest{MaxAge: seconds(3600)},
			authAt: now.Add(-10 * time.Minute),
			want:   false,
		},
		{
			name:   "max_age rejects one outside it",
			req:    AuthRequest{MaxAge: seconds(60)},
			authAt: now.Add(-10 * time.Minute),
			want:   true,
		},
		{
			// oidcc-max-age-1 turns on this: one second is short enough that
			// any real session has already aged past it, so treating a zero or
			// tiny max_age as "no constraint" would pass the parameter and fail
			// the intent.
			name:   "max_age=0 requires a new authentication every time",
			req:    AuthRequest{MaxAge: seconds(0)},
			authAt: now.Add(-time.Second),
			want:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.req.RequiresFreshAuthentication(tc.authAt); got != tc.want {
				t.Errorf("RequiresFreshAuthentication = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPromptedFor(t *testing.T) {
	req := AuthRequest{Prompt: []string{"none", "consent"}}
	for value, want := range map[string]bool{
		"none": true, "consent": true, "login": false, "": false,
	} {
		if got := req.PromptedFor(value); got != want {
			t.Errorf("PromptedFor(%q) = %v, want %v", value, got, want)
		}
	}
}
