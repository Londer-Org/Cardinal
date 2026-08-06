import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ErrorMessage } from '@/components/ErrorMessage'
import { api, queryKeys, type Me } from '@/lib/api'

/**
 * Your own details, and the only place they can be changed.
 *
 * These are what an application receives when it asks for the `profile` and
 * `email` scopes, so an account with neither set shows up in every connected
 * application as a UUID and nothing else — which is how this screen came to
 * exist.
 *
 * The login is shown but not editable. It appears in policy, in group listings
 * and in every audit record a colleague reads, so renaming is an administrative
 * act rather than a self-service one.
 */
export function ProfileCard({ session }: { session: Me }) {
  const queryClient = useQueryClient()

  const [displayName, setDisplayName] = useState(session.displayName)
  const [email, setEmail] = useState(session.email)
  const [saved, setSaved] = useState(false)

  const save = useMutation({
    mutationFn: () =>
      api.auth.updateProfile({ displayName: displayName.trim(), email: email.trim() }),
    onSuccess: (updated) => {
      queryClient.setQueryData(queryKeys.me, updated)
      setSaved(true)
      setTimeout(() => { setSaved(false) }, 2500)
    },
  })

  const dirty =
    displayName.trim() !== session.displayName || email.trim() !== session.email

  return (
    <Card>
      <CardHeader>
        <CardTitle>Your details</CardTitle>
        <CardDescription>
          What applications see when they ask who you are.
        </CardDescription>
      </CardHeader>

      <CardContent>
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            save.mutate()
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="profile-login">Username</Label>
            <Input id="profile-login" value={session.login} disabled readOnly />
            <p className="text-xs text-muted-foreground">
              Set by an administrator. It appears in policy and in the audit
              trail, so it is not yours to change.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="profile-name">Display name</Label>
            <Input
              id="profile-name"
              value={displayName}
              onChange={(event) => { setDisplayName(event.target.value) }}
              placeholder="How your name should appear"
              autoComplete="name"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="profile-email">Email</Label>
            <Input
              id="profile-email"
              type="email"
              value={email}
              onChange={(event) => { setEmail(event.target.value) }}
              placeholder="you@example.com"
              autoComplete="email"
            />
            <p className="text-xs text-muted-foreground">
              {/* Said plainly rather than implied by a missing tick. A relying
                  party that treated this as verified would be trusting a claim
                  nobody checked. */}
              Not verified — Cardinal has not confirmed you can receive mail
              here, and tells applications so.
            </p>
          </div>

          <ErrorMessage error={save.error} />

          <div className="flex items-center gap-3">
            <Button type="submit" disabled={!dirty || save.isPending}>
              {save.isPending ? 'Saving…' : 'Save'}
            </Button>
            {saved && !dirty && (
              <span className="text-sm text-muted-foreground">Saved.</span>
            )}
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
