import { z } from 'zod'

/**
 * What the browser sends, described once.
 *
 * The response half of the contract lives in schemas.ts and has been parsed at
 * the boundary since the beginning. This is the other direction, which was not
 * described anywhere: request bodies were assembled inline in nine components,
 * each doing its own `.trim()`, relying on HTML `required`, and hoping the
 * server agreed.
 *
 * Three things follow from having them here instead:
 *
 *   - **The type comes from the schema**, so a field renamed on one side is a
 *     type error rather than a silently dropped value. The hand-written
 *     `{ name: string; days: number }` inline in api/index.ts is what let
 *     `tokens.create` double-encode its body and 400 on every submission — the
 *     types matched, the values did not, and nothing checked.
 *
 *   - **The message is written once.** A rule the server enforces and the
 *     browser explains badly is a rule users hit twice.
 *
 *   - **Every mutating call parses its input**, not only the ones reached
 *     through a form. A component calling the client directly gets the same
 *     check.
 *
 * ## Two kinds of rule, and it matters which is which
 *
 * Client-side validation never enforces anything: the browser is under the
 * user's control, so the server is the only thing that decides. What these are
 * for is telling the person typing what will happen before they submit.
 *
 * That leaves two categories, and the first draft of this file blurred them —
 * it claimed every rule mirrored the server while requiring a display name the
 * server treats as optional and a reason the server defaults to empty. A form
 * that refuses what the API accepts is a bug, not caution: it makes valid states
 * unreachable, and the one that bit here was being unable to clear a display
 * name typed by mistake.
 *
 *   - **MIRRORS** — the same rule the server enforces, marked with the Go that
 *     owns it. If these drift, the console refuses things the API would take, or
 *     promises things it will not. Both are bugs.
 *
 *   - **CONSOLE** — a rule the console imposes and the server does not. Legal
 *     when the value is a human's to write and a blank one is useless to the
 *     next human, but it must be deliberate and labelled, because the CLI and
 *     the API will happily accept what this refuses.
 *
 * Some server rules cannot be mirrored at all and are noted where they appear:
 * whether an email is on a domain Cardinal is the identity provider for
 * (ADR 0009), and whether an http redirect URI is allowed, both depend on
 * configuration the browser cannot see.
 *
 * This is the argument for generating these from an OpenAPI spec rather than
 * writing them, which the plan calls for and which does not exist yet. Until it
 * does, the mirroring is manual and these comments are the only thing holding
 * it together.
 */

/**
 * An entity name: login, group name, application name, host name.
 *
 * MIRRORS `namePattern` and `ValidateName` in internal/directory/entity.go. The
 * constraint is not arbitrary — a name has to be safe to embed in a POSIX
 * passwd entry, an SSH certificate principal and a sudoers file, and the
 * intersection of those is narrow.
 */
export const entityName = z
  .string()
  .trim()
  .min(1, 'Required.')
  .max(63, 'At most 63 characters.')
  .refine((value) => value === value.toLowerCase(), 'Lowercase only.')
  .refine(
    (value) => /^[a-z0-9][a-z0-9._-]*$/.test(value),
    'Start with a letter or digit, then letters, digits, dot, underscore or hyphen.',
  )

/**
 * A display name — what a person or group is called, in their own words.
 *
 * MIRRORS the server, which caps it at 200 characters and requires nothing
 * else. Blank is permitted on purpose: `NewEntity` accepts an empty display
 * name, the create-person form says so in as many words, and profile updates
 * have to be able to clear one typed by mistake.
 *
 * Unconstrained beyond the length, and that is also deliberate: it holds names
 * in every script there is, and any rule about their shape would be a rule
 * about whose names are real.
 */
const displayName = z
  .string()
  .trim()
  .max(200, 'At most 200 characters.')

/**
 * Email, optional everywhere it appears.
 *
 * MIRRORS `mail.ParseAddress` in internal/httpapi/profile.go. An empty string
 * means "not set" rather than "invalid" — the profile form submits every field,
 * so blanking one has to be expressible.
 *
 * One server rule is not mirrored and cannot be: an address on a domain
 * Cardinal is the identity provider for is refused (ADR 0009), because an
 * outage would take the way back in along with the thing that is down. The
 * browser does not know which domain that is, so the refusal arrives from the
 * server.
 */
const optionalEmail = z.union([
  z.literal(''),
  z.email('That does not look like an email address.'),
])

export const updateProfileRequest = z.object({
  displayName,
  email: optionalEmail,
})
export type UpdateProfileRequest = z.infer<typeof updateProfileRequest>

export const createUserRequest = z.object({
  login: entityName,
  // Optional, and the form says so — they set their own when they enrol.
  displayName,
  // Almost always true. An account with no invitation has no way to enroll a
  // passkey, so it cannot be signed into until somebody issues one.
  invite: z.boolean(),
})
export type CreateUserRequest = z.infer<typeof createUserRequest>

export const createGroupRequest = z.object({
  name: entityName,
  displayName,
  // The application a group exists for, and optional — the form says so, and
  // most groups belong to no application at all. Unvalidated beyond being a
  // string because it is chosen from a list of names the server supplied.
  owner: z.string(),
})
export type CreateGroupRequest = z.infer<typeof createGroupRequest>

/**
 * Adding somebody to a group.
 *
 * `until` is optional and that is the interesting part: omitting it makes the
 * grant unbounded, which is the grant nobody revokes. The form defaults to a
 * bounded one for that reason, and the schema permits either.
 */
export const grantRequest = z.object({
  member: z.string().min(1, 'Choose who to add.'),
  until: z.union([z.literal(''), z.iso.datetime({ local: true })]).optional(),
  // CONSOLE. The server stores whatever arrives and defaults to empty. This is
  // the field somebody reads in six months when deciding whether a grant is
  // still justified, and an empty one makes that unanswerable — so the console
  // asks, while the CLI and API remain free not to.
  reason: z
    .string()
    .trim()
    .min(1, 'Say why — this is what somebody reads in six months.')
    .max(500, 'At most 500 characters.'),
})
export type GrantRequest = z.infer<typeof grantRequest>

/**
 * An OAuth redirect URI.
 *
 * MIRRORS `validateRedirectURI` in internal/store/oidcclient.go, which calls
 * these "the single most abused part of OAuth" and is right: an attacker who
 * can get a code delivered to a URI they control has the account.
 *
 * The http rule is deliberately *not* mirrored. The server permits http for
 * literal IP loopback per RFC 8252, and permits it more widely under dev mode —
 * conditions this schema cannot see, since dev mode is a sibling field. Guessing
 * would mean refusing registrations the server would accept, so the browser
 * checks the unconditional rules and leaves the conditional one to the server,
 * where the answer is actually known.
 */
export const redirectURI = z
  .string()
  .trim()
  .min(1, 'Required.')
  .refine((value) => !value.includes('*'),
    'No wildcards — an attacker controlling any matching host would receive ' +
    'authorization codes. Register each URI exactly.')
  .refine((value) => !value.includes('#'),
    'No fragment — the browser never sends it to the server, so it would be ' +
    'silently dropped.')
  .refine((value) => {
    try {
      return new URL(value).protocol !== ''
    } catch {
      return false
    }
  }, 'Must be an absolute URL, including the scheme.')

export const registerApplicationRequest = z.object({
  name: entityName,
  displayName,
  redirectUris: z
    .array(redirectURI)
    .min(1, 'At least one — a client with none can never complete a login.'),
  scopes: z.array(z.string()).min(1, 'At least one scope.'),
  confidential: z.boolean(),
  requireConsent: z.boolean(),
  devMode: z.boolean(),
})
export type RegisterApplicationRequest = z.infer<typeof registerApplicationRequest>

/**
 * A new access token.
 *
 * The lifetime bound MIRRORS `maxTokenTTL` in internal/httpapi/tokens.go: long
 * enough that nobody renews a build pipeline's token monthly, short enough that
 * a forgotten one in a forgotten repository stops working while the person who
 * created it is still around.
 */
export const createTokenRequest = z.object({
  // MIRRORS the handler, which refuses a blank name outright.
  name: z
    .string()
    .trim()
    .min(1, 'A name is how you tell four of them apart in six months.')
    .max(100, 'At most 100 characters.'),
  days: z
    .number()
    .int()
    .positive('Must be at least a day.')
    .max(365, 'A token may not last more than a year.'),
})
export type CreateTokenRequest = z.infer<typeof createTokenRequest>

/**
 * Naming a passkey.
 *
 * CONSOLE. What tells "the yubikey" from "the laptop" a year later, and the
 * screen that lists them is the one where somebody decides which to revoke.
 */
export const nameCredentialRequest = z.object({
  name: z
    .string()
    .trim()
    .min(1, 'Name it — "phone" and "yubikey" beat two blank rows.')
    // MIRRORS `webauthn_credentials_name_len` in migration 0003. Anything
    // longer reaches the database and comes back as a constraint violation,
    // which reads as a broken server rather than a too-long name.
    .max(64, 'At most 64 characters.'),
})
export type NameCredentialRequest = z.infer<typeof nameCredentialRequest>

/**
 * Opening a dual-control recovery.
 *
 * The reason is required and goes in front of the second administrator, who
 * decides whether to approve on the strength of it. "recovery" as a reason is
 * how dual control becomes a rubber stamp.
 */
export const openRecoveryRequest = z.object({
  login: entityName,
  // CONSOLE, and the strongest case for one. The server accepts an empty
  // reason; a second administrator then approves a recovery on the strength of
  // nothing, which is how dual control becomes a rubber stamp. Arguably the
  // server should require this too — that is a change to the API, not to a form,
  // so it is not made here.
  reason: z
    .string()
    .trim()
    .min(10, 'Another administrator approves on the strength of this. Say what happened.')
    .max(500, 'At most 500 characters.'),
})
export type OpenRecoveryRequest = z.infer<typeof openRecoveryRequest>

/** Issuing an enrollment invitation. Supersedes any outstanding link. */
export const issueInvitationRequest = z.object({ login: entityName })
export type IssueInvitationRequest = z.infer<typeof issueInvitationRequest>

/**
 * Finishing enrollment: the unauthenticated path to a first passkey.
 *
 * The invitation token authorises all of it, so the profile fields are the
 * new account's own description of itself rather than an administrator's.
 */
export const enrollRequest = z.object({
  displayName,
  email: optionalEmail,
})
export type EnrollRequest = z.infer<typeof enrollRequest>
