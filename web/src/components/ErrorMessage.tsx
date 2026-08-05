import { AlertCircleIcon } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { ApiError } from '@/lib/api'
import { WebAuthnError } from '@/lib/webauthn'

/**
 * Turns a thrown value into something a person can act on.
 *
 * WebAuthn and API errors already carry deliberately-worded messages; anything
 * else is unexpected and gets a neutral fallback rather than a stringified
 * object, which would leak internals into the UI and help nobody.
 */
export function messageFor(error: unknown): string {
  if (error instanceof WebAuthnError || error instanceof ApiError) {
    return error.message
  }
  if (error instanceof Error) {
    return error.message
  }
  return 'Something went wrong.'
}

export function ErrorMessage({ error }: { error: unknown }) {
  if (error === null || error === undefined) return null

  return (
    <Alert variant="destructive" className="mt-4">
      <AlertCircleIcon />
      <AlertDescription>{messageFor(error)}</AlertDescription>
    </Alert>
  )
}
