package policy

import (
	"testing"
	"time"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/server/claims"
)

// Host access, which is the FreeIPA HBAC replacement.
//
// The interesting property is that it needs no new kind of object. A host is a
// directory entity, so "which machines" is group membership; a person's access
// is group membership; and the local account is the one fact with nowhere else
// to live, so it travels in the context.
//
// These tests exist because the resource half of that is easy to get wrong in a
// way that looks like it works: a resource reaching Cedar without parents makes
// every `resource in …` clause match nothing, and a policy that never matches
// is indistinguishable from a policy that is correctly refusing.

const hostAccessPolicy = `
@id("sre-may-log-into-production")
permit (
    principal in Cardinal::Group::"` + groupSRE + `",
    action == Cardinal::Action::"SSHLogin",
    resource in Cardinal::Group::"` + groupProd + `"
)
when {
    context.localAccount == "deploy"
};
`

// Fixed identifiers, because Cedar policy text references groups by id and a
// generated one cannot appear in a literal.
const (
	groupSRE   = "11111111-1111-7111-8111-111111111111"
	groupProd  = "22222222-2222-7222-8222-222222222222"
	groupOther = "33333333-3333-7333-8333-333333333333"
)

func hostAccessEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine([]byte(hostAccessPolicy), 1)
	if err != nil {
		t.Fatalf("compiling the test policy: %v", err)
	}
	return engine
}

func person(groups ...string) *claims.Subject {
	s := &claims.Subject{
		ID:    uuid.MustParse("44444444-4444-7444-8444-444444444444"),
		Login: "alonfils",
		Auth: claims.AuthContext{
			Method:      "passkey",
			At:          time.Now(),
			DeviceBound: true,
		},
	}
	for _, g := range groups {
		s.Groups = append(s.Groups, claims.Group{
			ID: uuid.MustParse(g), Name: g, Depth: 1,
		})
	}
	return s
}

func hostIn(groups ...string) []claims.Group {
	out := make([]claims.Group, 0, len(groups))
	for _, g := range groups {
		out = append(out, claims.Group{ID: uuid.MustParse(g), Name: g, Depth: 1})
	}
	return out
}

func askSSH(t *testing.T, e *Engine, subject *claims.Subject, hostGroups []claims.Group, account string) Decision {
	t.Helper()
	return e.Evaluate(Request{
		Subject:        subject,
		Action:         ActionSSHLogin,
		Resource:       types.NewEntityUID(TypeHost, "web-01.prod"),
		ResourceGroups: hostGroups,
		Context: map[string]types.Value{
			"localAccount": types.String(account),
		},
	})
}

// TestMemberOfBothGroupsMayLogIn is the case the whole design is for.
func TestMemberOfBothGroupsMayLogIn(t *testing.T) {
	e := hostAccessEngine(t)

	got := askSSH(t, e, person(groupSRE), hostIn(groupProd), "deploy")
	if !got.Allowed {
		t.Fatalf("an SRE was refused a production host: %v %v", got.Reasons, got.Errors)
	}
	if len(got.Errors) > 0 {
		t.Errorf("policy evaluation errors: %v", got.Errors)
	}
}

// TestHostGroupIsLoadBearing.
//
// The same person, the same account, a host in a different group. If this
// passes, the resource is not being matched at all and the previous test proved
// nothing — which is exactly the failure that a policy silently matching
// nothing produces.
func TestHostGroupIsLoadBearing(t *testing.T) {
	e := hostAccessEngine(t)

	got := askSSH(t, e, person(groupSRE), hostIn(groupOther), "deploy")
	if got.Allowed {
		t.Fatal("an SRE reached a host outside the group the policy names, so " +
			"the resource clause is matching everything rather than something")
	}
}

// TestGroupMembershipIsLoadBearing is the same check from the principal side.
func TestGroupMembershipIsLoadBearing(t *testing.T) {
	e := hostAccessEngine(t)

	got := askSSH(t, e, person(groupOther), hostIn(groupProd), "deploy")
	if got.Allowed {
		t.Fatal("someone outside the permitted group reached a production host")
	}
}

// TestLocalAccountIsLoadBearing.
//
// The account is the authorization, not a label. A rule permitting `deploy`
// must not hand out a certificate good for anything else, or the principals in
// that certificate mean nothing.
func TestLocalAccountIsLoadBearing(t *testing.T) {
	e := hostAccessEngine(t)

	for _, account := range []string{"root", "www-data", "postgres", ""} {
		got := askSSH(t, e, person(groupSRE), hostIn(groupProd), account)
		if got.Allowed {
			t.Errorf("a rule permitting only `deploy` also permitted %q", account)
		}
	}
}

// TestResourceWithNoGroupsIsRefused.
//
// A host nobody has placed in a group is a host nobody has granted access to.
// Worth asserting because the failure mode of the resource projection is to
// leave the entity absent, and an absent entity must deny rather than error
// into something permissive.
func TestResourceWithNoGroupsIsRefused(t *testing.T) {
	e := hostAccessEngine(t)

	got := askSSH(t, e, person(groupSRE), nil, "deploy")
	if got.Allowed {
		t.Fatal("a host belonging to no group was reachable")
	}
}
