# ADR 0016: Cardinal serves its own discovery document

- **Status:** Accepted
- **Date:** 2026-08-06
- **Found by:** the OpenID Foundation conformance suite, on its first run.

## Context

`/.well-known/openid-configuration` was served by zitadel/oidc. It advertised:

| Advertised | Reality |
|---|---|
| `response_types_supported: [code, id_token, id_token token]` | every client offers `code` only |
| `grant_types_supported: […, implicit, …jwt-bearer]` | authorization code and refresh token |
| `device_authorization_endpoint` | not implemented; a POST returned Cardinal's **CSRF error** |
| `scopes_supported: […, phone, address]` | no telephone number or postal address exists in the directory |
| — | `groups` is implemented and was **not** advertised |

None of it is configurable. `ResponseTypes` is a fixed list in the library
carrying the comment `// TODO: ok for now, check later if dynamic needed`,
`GrantTypes` always appends `implicit`, and
`GrantTypeJWTAuthorizationSupported()` is a method whose entire body is
`return true`. The library is not at fault for a generic default; it simply
cannot know which of these a given deployment implements.

## Decision

Cardinal serves the document, building on `op.CreateDiscoveryConfig` and
overriding only the fields the library will not compute. Endpoints, signing
algorithms and the rest stay derived, so they cannot drift from what is
actually mounted.

## Consequences

Discovery is a contract, not documentation. A relying party reads it to choose
a flow; a conformance suite reads it to choose tests. Both are entitled to
assume that what it lists can be used, and the first honest reader of an
overstated document is the one who finds out it was wrong.

The effect is measurable in both directions. Advertising `phone` and `address`
produced conformance *warnings* — the suite requested those scopes and got
nothing back. Withdrawing them turned the same tests into `SKIPPED`, which is
the correct outcome for a scope a provider does not offer. Advertising `groups`
makes a feature discoverable that clients previously had to be told about out
of band.

Two things this does not fix:

- **`client_id` appears in every ID token.** `oidc.NewIDTokenClaims` sets it
  alongside `azp`, and no storage hook can remove a claim the library has
  already put on the struct. Cardinal never asks for it. It is redundant rather
  than harmful — `aud` and `azp` carry the same fact — and the suite reports it
  as a warning, so it is recorded rather than worked around. Fixing it means
  patching the dependency.
- **Serving discovery outside the library's issuer interceptor renders every
  endpoint as a bare path.** Found immediately after making this change, because
  the document came back with `/oidc/token` instead of an absolute URL and a
  relying party would have had nothing to resolve it against. The handler is
  wrapped in `op.NewIssuerInterceptor`, and a test asserts each endpoint is
  absolute against the issuer.

A test pins the whole document, because the failure mode here is a dependency
upgrade quietly handing the job back to the library — and an overstated
discovery document is the kind of defect that looks like nothing until a client
believes it.
