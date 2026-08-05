package claims_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestClaimsImportsNoProtocolPackages enforces the constraint ADR 0007 states.
//
// The claims package exists so OIDC, forwardAuth, SCIM and SSH certificate
// issuance all describe a subject the same way. The moment it imports one of
// their libraries, that library's model starts leaking into the shared
// representation and the other three inherit it.
//
// This is a test rather than a note in a document because the failure mode is
// gradual: nobody adds an OIDC import on purpose, they add it while fixing
// something else and it looks harmless.
//
// DIRECT imports only. Transitive dependencies travel through internal/store,
// which legitimately touches WebAuthn types to persist credentials — see the
// note on that below. What matters here is that claims itself never names a
// protocol type, which is what keeps its own API neutral.
func TestClaimsImportsNoProtocolPackages(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`,
		"github.com/arthur-lonfils/cardinal/internal/claims").Output()
	if err != nil {
		t.Fatalf("listing imports: %v", err)
	}

	forbidden := map[string]string{
		"go-webauthn":  "WebAuthn is one authentication method; claims must describe the result, not the mechanism",
		"zitadel/oidc": "OIDC claims are a serialisation of a Subject, not its definition",
		"zitadel/saml": "SAML is not implemented (ADR 0007) and must not arrive through the back door",
		"crewjam/saml": "SAML is not implemented (ADR 0007)",
		"cedar-go":     "policy consumes a Subject; a Subject must not know policy exists",
		"net/http":     "a transport-shaped dependency means the projection is being modelled around one consumer",
	}

	for dep := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		for pattern, why := range forbidden {
			if strings.Contains(dep, pattern) {
				t.Errorf("internal/claims imports %q\n  %s\n  See ADR 0007.", dep, why)
			}
		}
	}
}

// TestStoreCredentialCouplingIsKnown documents a coupling this test suite found
// and deliberately tolerates, so it is not rediscovered as a surprise.
//
// internal/store exposes RegisterCredential(*webauthn.Credential), which drags
// go-webauthn into the dependency graph of everything that touches the store —
// including claims, transitively.
//
// That is acceptable today: it is one function on the persistence layer, and
// splitting the store package to satisfy a dependency-graph aesthetic would
// trade a real simplicity for a notional one. It becomes worth revisiting if a
// second credential type (TOTP, or WebAuthn's successor) arrives and the store
// starts accumulating protocol types rather than holding one.
//
// The test asserts the coupling stays *narrow*: WebAuthn may reach the store,
// and nothing else may.
func TestStoreCredentialCouplingIsKnown(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`,
		"github.com/arthur-lonfils/cardinal/internal/store").Output()
	if err != nil {
		t.Fatalf("listing imports: %v", err)
	}

	unexpected := []string{"zitadel/oidc", "zitadel/saml", "crewjam/saml", "cedar-go"}
	for dep := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		for _, pattern := range unexpected {
			if strings.Contains(dep, pattern) {
				t.Errorf("internal/store imports %q — the persistence layer should not "+
					"know about protocols or policy; that belongs in the packages that "+
					"serve them", dep)
			}
		}
	}
}
