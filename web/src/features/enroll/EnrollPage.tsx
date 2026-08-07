import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useMutation, useQuery } from '@tanstack/react-query'
import { CheckCircle2Icon, KeyRoundIcon, ShieldAlertIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { CardinalMark } from '@/components/CardinalMark'
import { ErrorMessage } from '@/components/ErrorMessage'
import { api, enrollRequest } from '@/lib/api'
import { createCredential, isSupported } from '@/lib/webauthn'

/**
 * What somebody types on their way to a first passkey.
 *
 * Extends `enrollRequest` — the profile half the API takes — with the device
 * nickname, which is not part of that request because it names a credential
 * rather than an account.
 */
const enrollForm = enrollRequest.extend({
  keyName: z.string().trim().max(64, 'At most 64 characters.'),
})
type EnrollForm = z.infer<typeof enrollForm>

/** Reads the invitation token from the URL, if this is an enrollment link. */
export function invitationToken(): string | null {
  if (window.location.pathname !== '/enroll') return null
  return new URLSearchParams(window.location.search).get('token')
}

/**
 * Setting up an account from an invitation.
 *
 * The one screen a new person sees before they have any credential, so it does
 * three things at once: says whose account this is, takes the details that stop
 * the account being blank, and registers the passkey.
 *
 * It deliberately does not sign anyone in. Finishing here means going to the
 * sign-in page and using the key just registered, which proves it works while
 * the person is still in front of the screen rather than the next morning.
 */
export function EnrollPage({ token }: { token: string }) {
  const invitation = useQuery({
    queryKey: ['invitation', token],
    queryFn: () => api.enroll.details(token),
    retry: false,
  })

  const [done, setDone] = useState(false)

  const form = useForm<EnrollForm>({
    resolver: zodResolver(enrollForm),
    defaultValues: { displayName: '', email: '', keyName: '' },
  })

  const enroll = useMutation({
    mutationFn: async (values: EnrollForm) => {
      const ceremony = await api.enroll.begin(token)
      const attestation = await createCredential(ceremony.options)
      return api.enroll.finish({
        token,
        ceremonyId: ceremony.ceremonyId,
        response: attestation,
        // Unlike the passkey list, blank is fine here and becomes "Passkey":
        // somebody registering their first credential has nothing to tell it
        // apart from yet, and a required field between them and an account is
        // a worse trade than a name they can change later.
        name: values.keyName === '' ? 'Passkey' : values.keyName,
        displayName: values.displayName,
        email: values.email,
      })
    },
    onSuccess: () => { setDone(true) },
  })

  if (!isSupported()) {
    return (
      <Shell>
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertTitle>Passkeys are not available</AlertTitle>
          <AlertDescription>
            Cardinal has no passwords, so setting up an account needs a browser
            that supports passkeys.
          </AlertDescription>
        </Alert>
      </Shell>
    )
  }

  if (invitation.isPending) {
    return <Shell><Skeleton className="h-64 w-full" /></Shell>
  }

  if (invitation.error !== null) {
    return (
      <Shell>
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertTitle>This invitation cannot be used</AlertTitle>
          <AlertDescription>
            <ErrorMessageText error={invitation.error} />
          </AlertDescription>
        </Alert>
      </Shell>
    )
  }

  if (done) {
    return (
      <Shell>
        <Card>
          <CardHeader>
            <CheckCircle2Icon className="size-8 text-muted-foreground" />
            <CardTitle className="pt-2">Your account is ready</CardTitle>
            <CardDescription>
              Sign in with the passkey you just registered.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button className="w-full" onClick={() => { window.location.replace('/') }}>
              Go to sign in
            </Button>
            <p className="mt-4 text-xs text-muted-foreground">
              {/* Said now, while they still have the device in hand. Two keys
                  is the difference between losing a device and losing the
                  account, and nobody comes back later to add a second. */}
              Once signed in, register a second passkey on a different device.
              With only one, losing it means losing the account.
            </p>
          </CardContent>
        </Card>
      </Shell>
    )
  }

  const details = invitation.data

  return (
    <Shell>
      <Card>
        <CardHeader>
          <CardinalMark className="size-10 text-foreground" />
          <CardTitle className="pt-2">Set up your account</CardTitle>
          <CardDescription>
            {/* The login is stated prominently and never editable. Someone
                opening a link out of a chat message has to be able to see whose
                account they are about to take possession of. */}
            You are setting up <span className="font-medium text-foreground">
              {details.login}
            </span>.
          </CardDescription>
        </CardHeader>

        <CardContent>
          {details.alreadyEnrolled && (
            <Alert className="mb-4 border-warning/50 text-warning-foreground [&>svg]:text-warning">
              <ShieldAlertIcon />
              <AlertTitle>This account already has a passkey</AlertTitle>
              <AlertDescription>
                Continuing adds another one. If you did not ask for this link,
                do not use it — tell whoever administers Cardinal.
              </AlertDescription>
            </Alert>
          )}

          <Form {...form}>
            <form
              className="space-y-4"
              onSubmit={(event) => {
                void form.handleSubmit((values) => { enroll.mutate(values) })(event)
              }}
            >
              <FormField
                control={form.control}
                name="displayName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Your name</FormLabel>
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
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="keyName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Name this device</FormLabel>
                    <FormControl>
                      <Input placeholder="Laptop, or YubiKey" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <ErrorMessage error={enroll.error} />

              <Button type="submit" className="w-full" disabled={enroll.isPending}>
                <KeyRoundIcon />
                {enroll.isPending ? 'Waiting for your device…' : 'Register a passkey'}
              </Button>

              <p className="text-xs text-muted-foreground">
                There is no password to choose. Your passkey stays on this
                device or your security key and cannot be phished or reused
                elsewhere.
              </p>
            </form>
          </Form>
        </CardContent>
      </Card>
    </Shell>
  )
}

function ErrorMessageText({ error }: { error: unknown }) {
  return <>{error instanceof Error ? error.message : 'Something went wrong.'}</>
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-h-dvh place-items-center bg-background p-6">
      <div className="w-full max-w-sm">{children}</div>
    </div>
  )
}
