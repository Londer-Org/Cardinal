import { z } from 'zod'

/**
 * The wire contract, described once.
 *
 * Every response is parsed through one of these at the boundary. `unknown` is
 * permitted in exactly one place — the value handed to `.parse()` in client.ts —
 * and nowhere else, so untyped data never travels more than a line from where it
 * entered. See ADR 0008.
 *
 * These are hand-written today. Once the OpenAPI spec is generated from the Go
 * handlers (Phase 2), they get generated from it: hand-maintained validation
 * drifts from the server, and in an identity system that drift is a security
 * bug rather than a papercut.
 */

export const meSchema = z.object({
  id: z.string(),
  login: z.string(),
  displayName: z.string(),
  authMethod: z.string(),
  authAt: z.string(),
  deviceBound: z.boolean(),
  emergency: z.boolean(),
  fullyEnrolled: z.boolean(),
  recoveryCodesRemaining: z.number(),
})
export type Me = z.infer<typeof meSchema>

export const credentialSchema = z.object({
  id: z.string(),
  name: z.string(),
  createdAt: z.string(),
  lastUsedAt: z.string().nullable(),
  backupEligible: z.boolean(),
  deviceBound: z.boolean(),
})
export type Credential = z.infer<typeof credentialSchema>

export const credentialsSchema = z.array(credentialSchema)

export const ceremonySchema = z.object({
  ceremonyId: z.string(),
  // Handed straight to the browser's WebAuthn API, which validates it and
  // rejects anything malformed. Re-describing the whole PublicKeyCredential
  // option surface here would add a second spec to maintain without adding a
  // check the platform does not already perform.
  options: z.unknown(),
})
export type Ceremony = z.infer<typeof ceremonySchema>

export const recoveryCodesSchema = z.object({
  codes: z.array(z.string()),
  note: z.string(),
})
export type RecoveryCodes = z.infer<typeof recoveryCodesSchema>

export const breakGlassChallengeSchema = z.object({
  challenge: z.string(),
  expiresAt: z.string(),
  command: z.string(),
})
export type BreakGlassChallenge = z.infer<typeof breakGlassChallengeSchema>

export const errorSchema = z.object({ error: z.string() })
