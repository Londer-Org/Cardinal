import { AlertCircleIcon } from 'lucide-react'
import { z } from 'zod'
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
  // A ZodError is an Error, and its `message` is a JSON dump of every issue.
  // Rendering that would be worse than the fallback, so the messages are joined
  // instead — they are written to be read, since the same strings appear under
  // the fields when a form catches this first.
  //
  // Reaching here at all means a caller bypassed a form, because the resolver
  // stops a bad submission before the client is touched.
  if (error instanceof z.ZodError) {
    return error.issues.map((issue) => issue.message).join(' ')
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
