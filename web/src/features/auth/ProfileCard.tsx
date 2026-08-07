import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ErrorMessage } from '@/components/ErrorMessage'
import {
  api,
  queryKeys,
  updateProfileRequest,
  type Me,
  type UpdateProfileRequest,
} from '@/lib/api'

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

  const [saved, setSaved] = useState(false)

  const form = useForm<UpdateProfileRequest>({
    resolver: zodResolver(updateProfileRequest),
    defaultValues: { displayName: session.displayName, email: session.email },
  })

  const save = useMutation({
    mutationFn: api.auth.updateProfile,
    onSuccess: (updated) => {
      queryClient.setQueryData(queryKeys.me, updated)
      // Reset to what came back, so the form is clean against the saved values
      // rather than against what was typed — they differ whenever the server
      // normalises anything.
      form.reset({ displayName: updated.displayName, email: updated.email })
      setSaved(true)
      setTimeout(() => { setSaved(false) }, 2500)
    },
  })

  const dirty = form.formState.isDirty

  return (
    <Card>
      <CardHeader>
        <CardTitle>Your details</CardTitle>
        <CardDescription>
          What applications see when they ask who you are.
        </CardDescription>
      </CardHeader>

      <CardContent>
        <Form {...form}>
          <form
            className="space-y-4"
            onSubmit={(event) => {
              void form.handleSubmit((values) => { save.mutate(values) })(event)
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

            <FormField
              control={form.control}
              name="displayName"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Display name</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="How your name should appear"
                      autoComplete="name"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email</FormLabel>
                  <FormControl>
                    <Input
                      type="email"
                      placeholder="you@example.com"
                      autoComplete="email"
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    {/* Said plainly rather than implied by a missing tick. A
                        relying party that treated this as verified would be
                        trusting a claim nobody checked. */}
                    Not verified — Cardinal has not confirmed you can receive
                    mail here, and tells applications so.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

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
        </Form>
      </CardContent>
    </Card>
  )
}
