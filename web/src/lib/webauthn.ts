/**
 * Bridges the browser's WebAuthn API and Cardinal's JSON wire format.
 *
 * WebAuthn passes ArrayBuffers, JSON cannot carry them, and the spec settled on
 * base64url. Almost every WebAuthn integration bug is a base64 vs base64url
 * mix-up in this layer, so the conversions live in one place with tests
 * possible around them rather than being inlined at each call site.
 */

/** base64url has no padding and uses - and _ in place of + and /. */
export function base64urlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

export function bytesToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Server-issued options, before ArrayBuffer fields are decoded. */
interface EncodedCredentialOptions {
  readonly publicKey: {
    readonly challenge: string
    readonly user?: { readonly id: string; readonly name: string; readonly displayName: string }
    readonly excludeCredentials?: readonly { readonly id: string; readonly type: string }[]
    readonly allowCredentials?: readonly { readonly id: string; readonly type: string }[]
    readonly [key: string]: unknown
  }
}

function isEncodedOptions(value: unknown): value is EncodedCredentialOptions {
  return (
    typeof value === 'object' &&
    value !== null &&
    'publicKey' in value &&
    typeof value.publicKey === 'object'
  )
}

/** Thrown when the user cancels or no authenticator is available. */
export class WebAuthnError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'WebAuthnError'
  }
}

export function isSupported(): boolean {
  return typeof window.PublicKeyCredential === 'function'
}

/**
 * Reports whether the platform can create a passkey without external hardware.
 * Used only to phrase the prompt helpfully — never to decide what is allowed,
 * which is the server's job.
 */
export async function hasPlatformAuthenticator(): Promise<boolean> {
  if (!isSupported()) return false
  try {
    return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  } catch {
    return false
  }
}

function decodeOptions(raw: unknown): PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions {
  if (!isEncodedOptions(raw)) {
    throw new WebAuthnError('The server sent malformed authentication options.')
  }
  const pk = raw.publicKey

  const decoded: Record<string, unknown> = { ...pk }
  decoded['challenge'] = base64urlToBytes(pk.challenge)

  if (pk.user) {
    decoded['user'] = { ...pk.user, id: base64urlToBytes(pk.user.id) }
  }
  for (const key of ['excludeCredentials', 'allowCredentials'] as const) {
    const list = pk[key]
    if (list) {
      decoded[key] = list.map((c) => ({ ...c, id: base64urlToBytes(c.id) }))
    }
  }
  return decoded as unknown as PublicKeyCredentialCreationOptions
}

/** Encodes a credential for transport back to the server. */
function encodeCredential(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response
  const encoded: Record<string, unknown> = {
    id: credential.id,
    rawId: bytesToBase64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
  }

  if (response instanceof AuthenticatorAttestationResponse) {
    encoded['response'] = {
      clientDataJSON: bytesToBase64url(response.clientDataJSON),
      attestationObject: bytesToBase64url(response.attestationObject),
      transports: response.getTransports(),
    }
  } else if (response instanceof AuthenticatorAssertionResponse) {
    encoded['response'] = {
      clientDataJSON: bytesToBase64url(response.clientDataJSON),
      authenticatorData: bytesToBase64url(response.authenticatorData),
      signature: bytesToBase64url(response.signature),
      // Present for discoverable credentials; it is what identifies the account
      // in a usernameless login.
      userHandle: response.userHandle ? bytesToBase64url(response.userHandle) : null,
    }
  } else {
    throw new WebAuthnError('Unrecognised authenticator response.')
  }

  return encoded
}

/** Runs a registration ceremony. */
export async function createCredential(rawOptions: unknown): Promise<Record<string, unknown>> {
  const publicKey = decodeOptions(rawOptions) as PublicKeyCredentialCreationOptions
  let credential: Credential | null
  try {
    credential = await navigator.credentials.create({ publicKey })
  } catch (cause) {
    throw new WebAuthnError(describeFailure(cause), { cause })
  }
  if (!(credential instanceof PublicKeyCredential)) {
    throw new WebAuthnError('No credential was created.')
  }
  return encodeCredential(credential)
}

/** Runs an authentication ceremony. */
export async function getCredential(rawOptions: unknown): Promise<Record<string, unknown>> {
  const publicKey = decodeOptions(rawOptions) as PublicKeyCredentialRequestOptions
  let credential: Credential | null
  try {
    credential = await navigator.credentials.get({ publicKey })
  } catch (cause) {
    throw new WebAuthnError(describeFailure(cause), { cause })
  }
  if (!(credential instanceof PublicKeyCredential)) {
    throw new WebAuthnError('No credential was returned.')
  }
  return encodeCredential(credential)
}

/**
 * Turns a DOMException into something a person can act on.
 *
 * The platform's own messages are famously unhelpful ("The operation either
 * timed out or was not allowed"), and a user who cannot tell "you cancelled"
 * from "this key is already registered" will simply try the same thing again.
 */
function describeFailure(cause: unknown): string {
  if (!(cause instanceof DOMException)) {
    return 'Authentication failed.'
  }
  switch (cause.name) {
    case 'NotAllowedError':
      return 'Cancelled, or the request timed out. Try again and confirm on your device.'
    case 'InvalidStateError':
      return 'This authenticator is already registered to your account.'
    case 'NotSupportedError':
      return 'This device cannot create the kind of passkey Cardinal requires.'
    case 'SecurityError':
      return 'This page is not being served from an origin Cardinal trusts.'
    case 'AbortError':
      return 'The request was cancelled.'
    default:
      return `Authentication failed (${cause.name}).`
  }
}
