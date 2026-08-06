import { useState } from 'react'
import { CopyIcon, MailIcon, ShieldAlertIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { ErrorMessage } from '@/components/ErrorMessage'
import type { DirectoryUserDetail } from '@/lib/api'
import { useIssueInvitation, useRevokeInvitation } from './useDirectory'

/**
 * Issuing, re-issuing and withdrawing someone's enrollment link.
 *
 * Links get lost, expire, and go to the wrong person, and until this existed the
 * only way to deal with any of that was a shell on the host — which is a strange
 * thing to need when an administrator is already looking at the account.
 *
 * Re-issuing supersedes the outstanding link server-side, so the old one stops
 * working the moment a replacement is made. That is what makes "it went to the
 * wrong address" recoverable rather than merely regrettable.
 */
export function InvitationPanel({ user }: { user: DirectoryUserDetail }) {
  const issue = useIssueInvitation()
  const revoke = useRevokeInvitation()
  const [link, setLink] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  // An account that can already sign in is a recovery, not an onboarding, and
  // recovery takes two administrators (ADR 0015). Saying so beats offering a
  // button that returns a conflict.
  if (user.credentials > 0) {
    return (
      <div className="rounded-md border p-3">
        <p className="text-xs font-medium text-muted-foreground">Enrollment</p>
        <p className="mt-1 text-xs">
          {user.credentials} {user.credentials === 1 ? 'passkey' : 'passkeys'}{' '}
          registered. Restoring access to an account that can already sign in
          needs two administrators — open a recovery request rather than a new
          link.
        </p>
      </div>
    )
  }

  const pending = user.invitationExpiresAt !== null

  return (
    <div className="space-y-3 rounded-md border p-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-medium text-muted-foreground">Enrollment</p>
        {pending && (
          <span className="text-xs text-muted-foreground">
            <MailIcon className="mr-1 inline size-3" />
            expires {new Date(user.invitationExpiresAt ?? '').toLocaleString()}
          </span>
        )}
      </div>

      <p className="text-xs">
        {pending
          ? 'A link is outstanding. Re-issuing replaces it — the old one stops working immediately.'
          : 'No passkey and no outstanding link, so nobody can sign in to this account.'}
      </p>

      {link !== null && (
        <div className="space-y-2">
          <div className="flex gap-2">
            <code className="min-w-0 flex-1 truncate rounded-md border bg-muted px-3 py-2 font-mono text-xs">
              {link}
            </code>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                void navigator.clipboard.writeText(link).then(() => { setCopied(true) })
              }}
            >
              <CopyIcon />
              {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>
          <Alert>
            <ShieldAlertIcon />
            <AlertTitle>Shown once</AlertTitle>
            <AlertDescription>
              Only its hash is stored. Re-issue if you lose it — that supersedes
              this one.
            </AlertDescription>
          </Alert>
        </div>
      )}

      <ErrorMessage error={issue.error ?? revoke.error} />

      <div className="flex gap-2">
        <Button
          size="sm"
          variant="outline"
          disabled={issue.isPending}
          onClick={() => {
            setCopied(false)
            issue.mutate(user.login, {
              onSuccess: (issued) => { setLink(issued.url) },
            })
          }}
        >
          {issue.isPending
            ? 'Issuing…'
            : pending
              ? 'Re-issue link'
              : 'Issue link'}
        </Button>

        {pending && (
          <Button
            size="sm"
            variant="ghost"
            className="text-destructive"
            disabled={revoke.isPending}
            onClick={() => {
              setLink(null)
              revoke.mutate(user.login)
            }}
          >
            {revoke.isPending ? 'Withdrawing…' : 'Withdraw'}
          </Button>
        )}
      </div>
    </div>
  )
}
