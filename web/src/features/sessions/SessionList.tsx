import { useState } from 'react'
import { LaptopIcon, ShieldCheckIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import {
  useRevokeOtherSessions,
  useRevokeSession,
  useSessions,
} from '@/features/sessions/useSessions'
import type { Session } from '@/lib/api'

/**
 * Describes a User-Agent in a few words.
 *
 * A heuristic, and labelled as one: the full string is on the row's `title`, so
 * anybody who needs the truth can read it. Rendering the raw header instead
 * would be honest and useless — 120 characters of version numbers is not how
 * somebody recognises their own laptop.
 *
 * Order matters. Every Chromium browser claims to be Safari, Edge claims to be
 * Chrome, and Chrome claims to be both, so the most specific match has to win.
 */
function describeAgent(agent: string): string {
  if (agent === '') return ''

  const browser =
    /\bEdg\//.test(agent) ? 'Edge'
    : /\bOPR\//.test(agent) ? 'Opera'
    : /\bFirefox\//.test(agent) ? 'Firefox'
    : /\bChrome\//.test(agent) ? 'Chrome'
    : /\bSafari\//.test(agent) ? 'Safari'
    : null

  const platform =
    /\bAndroid\b/.test(agent) ? 'Android'
    : /\b(iPhone|iPad|iOS)\b/.test(agent) ? 'iOS'
    : /\bMac OS X\b/.test(agent) ? 'macOS'
    : /\bWindows\b/.test(agent) ? 'Windows'
    : /\bLinux\b/.test(agent) ? 'Linux'
    : null

  if (browser === null && platform === null) return ''
  if (browser === null) return platform ?? ''
  if (platform === null) return browser
  return `${browser} on ${platform}`
}

function when(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

function SessionRow({ session }: { session: Session }) {
  const revoke = useRevokeSession()
  const [confirming, setConfirming] = useState(false)

  const description = describeAgent(session.userAgent)

  return (
    <li
      className="flex items-start justify-between gap-3 border-b py-3 last:border-b-0"
      title={session.userAgent === '' ? undefined : session.userAgent}
    >
      <div className="min-w-0">
        <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
          <LaptopIcon className="size-4 shrink-0 text-muted-foreground" />
          {description === '' ? 'Unrecorded device' : description}
          {session.current && <Badge variant="secondary">This device</Badge>}
          {session.deviceBound && (
            <Badge variant="outline" className="font-normal">
              <ShieldCheckIcon />
              Hardware key
            </Badge>
          )}
        </p>

        <p className="mt-0.5 text-xs text-muted-foreground">
          {/* Started, not "last seen". There is deliberately no last_seen
              column — updating one on every request is the standard way to make
              Postgres session storage slow — so claiming one here would be
              inventing data. */}
          Signed in {when(session.startedAt)}
          {session.clientIp !== '' && ` · from ${session.clientIp}`}
        </p>
        <p className="text-xs text-muted-foreground">
          Idles out {when(session.expiresAt)} · ends {when(session.endsAt)}
        </p>
      </div>

      {confirming ? (
        <div className="flex shrink-0 gap-2">
          <Button variant="outline" size="sm" onClick={() => { setConfirming(false) }}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            size="sm"
            disabled={revoke.isPending}
            onClick={() => {
              revoke.mutate(session.id, {
                onSuccess: () => {
                  // Revoking the one you are using is signing out. The server
                  // has already cleared the cookie; reloading is what stops the
                  // console sitting on a credential it will be refused for.
                  if (session.current) window.location.replace('/')
                },
              })
            }}
          >
            {session.current ? 'Sign out' : 'Revoke'}
          </Button>
        </div>
      ) : (
        <Button
          variant="ghost"
          size="sm"
          className="shrink-0 text-destructive"
          onClick={() => { setConfirming(true) }}
        >
          {session.current ? 'Sign out' : 'Revoke'}
        </Button>
      )}
    </li>
  )
}

/**
 * Where you are signed in, and the button that ends it.
 *
 * Nothing could see a session before this — not its owner, not an
 * administrator, not the CLI. Revocation existed in the store with two internal
 * callers, so "I think someone else is signed in as me" had no answer and "am I
 * still signed in on the laptop I sold" was unknowable.
 */
export function SessionList() {
  const { data, isPending, error } = useSessions()
  const revokeOthers = useRevokeOtherSessions()
  const [confirmingAll, setConfirmingAll] = useState(false)

  const sessions = data?.sessions ?? []
  const others = sessions.filter((s) => !s.current).length

  return (
    <Card>
      <CardHeader>
        <CardTitle>Where you are signed in</CardTitle>
        <CardDescription>
          Every browser holding a live session. One you do not recognise is one
          to end — and then register a new passkey, since whoever opened it used
          the one you have.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        <ErrorMessage error={error ?? revokeOthers.error} />

        {isPending ? (
          <div className="space-y-2">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
          </div>
        ) : (
          <ul>
            {sessions.map((session) => (
              <SessionRow key={session.id} session={session} />
            ))}
          </ul>
        )}

        {others > 0 && (
          <>
            <Separator />
            {confirmingAll ? (
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm">
                  End {others} other {others === 1 ? 'session' : 'sessions'}?
                  You stay signed in here.
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => { setConfirmingAll(false) }}
                >
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  disabled={revokeOthers.isPending}
                  onClick={() => {
                    revokeOthers.mutate(undefined, {
                      onSuccess: () => { setConfirmingAll(false) },
                    })
                  }}
                >
                  {revokeOthers.isPending ? 'Signing out…' : 'End them'}
                </Button>
              </div>
            ) : (
              <Button
                variant="outline"
                size="sm"
                onClick={() => { setConfirmingAll(true) }}
              >
                Sign out everywhere else
              </Button>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
