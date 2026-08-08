import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Badge } from '@/components/ui/badge'
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
import { ErrorMessage } from '@/components/ErrorMessage'
import { useSetPosix, useUpdateUser } from '@/features/directory/useDirectory'
import {
  adminProfileRequest,
  posixRequest,
  type AdminProfileRequest,
  type DirectoryUserDetail,
  type PosixRequest,
} from '@/lib/api'

/**
 * Somebody else's details.
 *
 * Separate from the login, which has its own dialog: renaming has consequences
 * a profile form should not quietly carry, and folding the two together is how
 * a login gets changed by somebody meaning to fix a typo in a display name.
 */
export function UserProfileCard({ user }: { user: DirectoryUserDetail }) {
  const update = useUpdateUser(user.login)

  const form = useForm<AdminProfileRequest>({
    resolver: zodResolver(adminProfileRequest),
    defaultValues: { displayName: user.displayName, email: user.email },
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Details</CardTitle>
        <CardDescription>
          What applications receive when they ask who this is. They can edit
          these themselves; this is here for the corrections they cannot make —
          a name typed wrong at onboarding, an address that bounces.
        </CardDescription>
      </CardHeader>

      <CardContent>
        <Form {...form}>
          <form
            className="space-y-4"
            onSubmit={(event) => {
              void form.handleSubmit((values) => {
                update.mutate(values, {
                  onSuccess: (saved) => { form.reset(saved) },
                })
              })(event)
            }}
          >
            <FormField
              control={form.control}
              name="displayName"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Display name</FormLabel>
                  <FormControl>
                    <Input placeholder="J Doe" {...field} />
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
                    <Input type="email" placeholder="you@example.com" {...field} />
                  </FormControl>
                  <FormDescription>
                    Not verified, and applications are told so. An address on a
                    domain Cardinal is the identity provider for is refused —
                    an outage would take the way back in along with the thing
                    that is down.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <ErrorMessage error={update.error} />

            <Button
              type="submit"
              size="sm"
              disabled={update.isPending || !form.formState.isDirty}
            >
              {update.isPending ? 'Saving…' : 'Save'}
            </Button>
          </form>
        </Form>
      </CardContent>
    </Card>
  )
}

/**
 * The uid, and what comes with it.
 *
 * There is no field for the number. It is allocated once and is permanent —
 * every file on every disk records it — so offering to edit it would be
 * offering a mistake that cannot be corrected once a host has been told.
 * `cardinal posix adopt` exists for the one window where it can still change.
 */
export function PosixCard({ user }: { user: DirectoryUserDetail }) {
  const assign = useSetPosix(user.login)

  const form = useForm<PosixRequest>({
    resolver: zodResolver(posixRequest),
    defaultValues: {
      homeDirectory: user.posix?.homeDirectory ?? `/home/${user.login}`,
      loginShell: user.posix?.loginShell ?? '/bin/bash',
    },
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Linux identity</CardTitle>
        <CardDescription>
          {user.posix === null
            ? 'No uid. Hosts cannot resolve this account, so nobody can log into a machine as them however policy is written.'
            : 'What `getent passwd` reports on every host this account may reach.'}
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {user.posix !== null && (
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-medium">uid {user.posix.uid}</span>
            {user.posix.adoptable ? (
              <Badge variant="outline" className="font-normal">
                Not yet served
              </Badge>
            ) : (
              <Badge variant="secondary">On disk</Badge>
            )}
            <span className="text-xs text-muted-foreground">
              {user.posix.adoptable
                ? // The only window in which the number can change: nothing has
                  // written it to a filesystem yet, so `cardinal posix adopt`
                  // can still match it to an existing system's number.
                  'No host has been told this number yet, so it can still be changed to match an existing system.'
                : 'A host has served this number, so files carry it. It is permanent now.'}
            </span>
          </div>
        )}

        <Form {...form}>
          <form
            className="space-y-4"
            onSubmit={(event) => {
              void form.handleSubmit((values) => { assign.mutate(values) })(event)
            }}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <FormField
                control={form.control}
                name="homeDirectory"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Home directory</FormLabel>
                    <FormControl>
                      <Input placeholder="/home/jdoe" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="loginShell"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Login shell</FormLabel>
                    <FormControl>
                      <Input placeholder="/bin/bash" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <ErrorMessage error={assign.error} />

            <Button type="submit" size="sm" disabled={assign.isPending}>
              {assign.isPending
                ? 'Saving…'
                : user.posix === null
                  ? 'Give them a uid'
                  : 'Save'}
            </Button>
          </form>
        </Form>
      </CardContent>
    </Card>
  )
}
