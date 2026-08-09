package scim_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/server/scim"
)

// TestParsesWhatIdentityProvidersSend.
//
// One equality on the resource's natural key is what reconciliation actually
// uses, and it is the whole supported grammar.
func TestParsesWhatIdentityProvidersSend(t *testing.T) {
	for raw, want := range map[string]scim.Filter{
		`userName eq "ada@example.com"`:    {Attribute: "username", Value: "ada@example.com"},
		`userName Eq "ada"`:                {Attribute: "username", Value: "ada"},
		`displayName eq "Engineering"`:     {Attribute: "displayname", Value: "Engineering"},
		`externalId eq "8f14e45f"`:         {Attribute: "externalid", Value: "8f14e45f"},
		`displayName eq "Ops \"on call\""`: {Attribute: "displayname", Value: `Ops "on call"`},
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := scim.ParseFilter(raw)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, want, *got)
		})
	}
}

// TestAnEmptyFilterListsEverything: the commonest request of all, and not an
// error.
func TestAnEmptyFilterListsEverything(t *testing.T) {
	got, err := scim.ParseFilter("   ")
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestCompoundFiltersAreRefusedRatherThanApproximated.
//
// The important half. A filter silently misread returns the wrong people and a
// provisioning client acts on the answer — so anything outside the supported
// grammar is a refusal a client can fall back from, not a guess.
func TestCompoundFiltersAreRefusedRatherThanApproximated(t *testing.T) {
	for _, raw := range []string{
		`userName eq "ada" and active eq true`,
		`userName eq "ada" or userName eq "grace"`,
		`not (userName eq "ada")`,
		`userName co "ada"`,
		`userName sw "a"`,
		`userName pr`,
		`emails[type eq "work"].value eq "ada@example.com"`,
		`userName eq ada`,
		`userName eq "unterminated`,
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := scim.ParseFilter(raw)
			assert.Nil(t, got)
			require.Error(t, err, "an unsupported filter was parsed into something")

			var unsupported scim.ErrUnsupportedFilter
			assert.ErrorAs(t, err, &unsupported)
			assert.Contains(t, err.Error(), "rather than approximating",
				"the refusal must say why, or a client author assumes a bug")
		})
	}
}

// TestAValueContainingEqSurvives: a display name may legitimately contain the
// substring this splits on, and splitting on the first one is what keeps that
// working.
func TestAValueContainingEqSurvives(t *testing.T) {
	got, err := scim.ParseFilter(`displayName eq "things eq other things"`)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "things eq other things", got.Value)
}
