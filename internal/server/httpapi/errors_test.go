package httpapi

import "testing"

// TestClientErrorsDoNotCarryPackageNames.
//
// Cardinal's errors are wrapped `fmt.Errorf("store: ...")` so a log line says
// which layer failed. Three dozen handlers pass err.Error() straight to the
// client, and the prefix goes with it — an administrator correcting a typo in
// a hostname was told "store: a hostname cannot be blank". Both observed
// against the running stack before this was written.
func TestClientErrorsDoNotCarryPackageNames(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		message string
		want    string
	}{
		{"store: a hostname cannot be blank", "a hostname cannot be blank"},
		{
			"temporal: a group cannot be a member of itself",
			"a group cannot be a member of itself",
		},
		{"directory: entity not found", "entity not found"},

		// One prefix, not every one it happens to start with. A message that
		// genuinely begins by naming a layer twice is not a thing that occurs,
		// and stripping in a loop would eat the sentence.
		{"store: store: doubled", "store: doubled"},

		// Messages that merely contain a colon keep it. This is the reason the
		// list is explicit rather than a pattern matching anything before one.
		{
			"the endpoint must be an absolute URL, such as https://app.example.com/events",
			"the endpoint must be an absolute URL, such as https://app.example.com/events",
		},
		{"expected fingerprint:timestamp:signature", "expected fingerprint:timestamp:signature"},
		{"could not reach 10.0.0.1:5432", "could not reach 10.0.0.1:5432"},

		// A word that starts like a prefix but is the sentence.
		{"storefront is not a known type", "storefront is not a known type"},
		{"", ""},
	} {
		t.Run(tc.message, func(t *testing.T) {
			t.Parallel()

			if got := withoutPackagePrefix(tc.message); got != tc.want {
				t.Errorf("withoutPackagePrefix(%q) = %q, want %q", tc.message, got, tc.want)
			}
		})
	}
}
