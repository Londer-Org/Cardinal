package store_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// TestHostnameResolvesToItsApplication is the whole point: forwardAuth is given
// a hostname and needs an entity, because "who may reach this" is that entity's
// group membership.
func TestHostnameResolvesToItsApplication(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	app := mustCreate(t, s, directory.TypeApplication, "grafana")
	require.NoError(t, s.AddApplicationHostname(ctx, app.ID, "grafana.example.com", nil))

	found, err := s.ApplicationForHostname(ctx, "grafana.example.com")
	require.NoError(t, err)
	assert.Equal(t, app.ID, found.ID)
}

// TestAnUnregisteredHostnameResolvesToNothing.
//
// The behaviour that replaced a function returning "staff" for every hostname,
// which made the shipped rule for staff applications admit every authenticated
// principal to every protected URL while reading as though it distinguished
// between them.
func TestAnUnregisteredHostnameResolvesToNothing(t *testing.T) {
	s := newStore(t)

	_, err := s.ApplicationForHostname(t.Context(), "nobody-registered-this.example.com")
	require.ErrorIs(t, err, directory.ErrNotFound)
}

// TestTwoApplicationsCannotHoldOneHostname.
//
// Whichever row won would decide which application's group memberships govern
// the request, so an ambiguous hostname is a request authorized against the
// wrong rules. The same refusal host aliases make, for the same reason.
func TestTwoApplicationsCannotHoldOneHostname(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	first := mustCreate(t, s, directory.TypeApplication, "grafana")
	second := mustCreate(t, s, directory.TypeApplication, "payroll")

	require.NoError(t, s.AddApplicationHostname(ctx, first.ID, "dash.example.com", nil))

	err := s.AddApplicationHostname(ctx, second.ID, "dash.example.com", nil)
	require.ErrorIs(t, err, store.ErrHostnameTaken)
}

// TestOnlyAnApplicationHoldsAHostname.
//
// The foreign key would accept a host or a user. Either would put the wrong
// entity's group memberships in charge of who may reach a web application — a
// machine in env-prod would make its site reachable by everyone who may SSH to
// production.
func TestOnlyAnApplicationHoldsAHostname(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")

	err := s.AddApplicationHostname(ctx, host.ID, "web-01.example.com", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "application")
}

// TestHostnamesAreNormalised.
//
// DNS is case-insensitive and X-Forwarded-Host carries a port when the proxy is
// not on 443. Both would otherwise be a hostname that resolves to nothing and a
// 403 nobody can explain, since the address in the browser looks exactly like
// the one that was registered.
func TestHostnamesAreNormalised(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	app := mustCreate(t, s, directory.TypeApplication, "grafana")
	require.NoError(t, s.AddApplicationHostname(ctx, app.ID, "Grafana.Example.COM", nil))

	for _, asked := range []string{
		"grafana.example.com",
		"GRAFANA.EXAMPLE.COM",
		"grafana.example.com:8443",
		"  grafana.example.com  ",
	} {
		found, err := s.ApplicationForHostname(ctx, asked)
		require.NoError(t, err, "%q must resolve", asked)
		assert.Equal(t, app.ID, found.ID)
	}
}

// TestADisabledApplicationIsUnreachable.
//
// Disabling has to close every door in the same breath, or it is a half
// measure that reads as a whole one.
func TestADisabledApplicationIsUnreachable(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	app := mustCreate(t, s, directory.TypeApplication, "grafana")
	require.NoError(t, s.AddApplicationHostname(ctx, app.ID, "grafana.example.com", nil))
	require.NoError(t, s.DisableEntity(ctx, app.ID, nil))

	_, err := s.ApplicationForHostname(ctx, "grafana.example.com")
	require.ErrorIs(t, err, directory.ErrNotFound)
}

// TestRemovingAHostnameTakesEffectAtOnce.
//
// Unlike a certificate, which keeps working until it expires: forwardAuth asks
// on every request, so this is one of the few revocations here that is
// immediate rather than eventual.
func TestRemovingAHostnameTakesEffectAtOnce(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	app := mustCreate(t, s, directory.TypeApplication, "grafana")
	require.NoError(t, s.AddApplicationHostname(ctx, app.ID, "grafana.example.com", nil))
	require.NoError(t, s.RemoveApplicationHostname(ctx, app.ID, "grafana.example.com", nil))

	_, err := s.ApplicationForHostname(ctx, "grafana.example.com")
	require.ErrorIs(t, err, directory.ErrNotFound)
}

// TestListApplicationsIncludesTheOnesWithNoClient.
//
// The gap this closes: the console listed OIDC relying parties, so an
// application behind the proxy — no client id, nothing to sign in with —
// appeared nowhere, while being precisely the kind that needs a hostname
// adding before anything can reach it.
func TestListApplicationsIncludesTheOnesWithNoClient(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	proxied := mustCreate(t, s, directory.TypeApplication, "intranet")
	require.NoError(t, s.AddApplicationHostname(ctx, proxied.ID, "intranet.example.com", nil))
	mustCreate(t, s, directory.TypeApplication, "grafana")

	apps, err := s.ListApplications(ctx)
	require.NoError(t, err)
	require.Len(t, apps, 2)

	byName := map[string]store.ApplicationEntry{}
	for _, a := range apps {
		byName[a.Name] = a
	}

	assert.Equal(t, []string{"intranet.example.com"}, byName["intranet"].Hostnames)
	assert.Empty(t, byName["grafana"].Hostnames,
		"an application reached only over OIDC has no hostnames, which is not an error")
}

// TestRetiringAnApplicationReachesBothKinds.
//
// Disabling used to go through the OIDC client, so an application with no
// client could be created from the console and never retired from it — half a
// feature, which is the shape this project keeps finding.
func TestRetiringAnApplicationReachesBothKinds(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	app := mustCreate(t, s, directory.TypeApplication, "intranet")
	require.NoError(t, s.AddApplicationHostname(ctx, app.ID, "intranet.example.com", nil))

	require.NoError(t, s.SetApplicationEnabled(ctx, "intranet", false, nil))

	_, err := s.ApplicationForHostname(ctx, "intranet.example.com")
	require.ErrorIs(t, err, directory.ErrNotFound,
		"retiring must close the door through the proxy, not only the OIDC one")

	require.NoError(t, s.SetApplicationEnabled(ctx, "intranet", true, nil))
	found, err := s.ApplicationForHostname(ctx, "intranet.example.com")
	require.NoError(t, err)
	assert.Equal(t, app.ID, found.ID,
		"the hostname survives being retired — it is the application that was disabled")
}

// TestRetiringSomethingThatIsNotThere reports rather than succeeding quietly.
func TestRetiringSomethingThatIsNotThere(t *testing.T) {
	s := newStore(t)

	err := s.SetApplicationEnabled(t.Context(), "no-such-application", false, nil)
	require.ErrorIs(t, err, directory.ErrNotFound)
}
