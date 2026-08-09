import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { CopyIcon, PlusIcon, TriangleAlertIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
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
import { Switch } from '@/components/ui/switch'
import { ErrorMessage } from '@/components/ErrorMessage'
import { entityName, redirectURI, type RegisteredApplication } from '@/lib/api'
import { useCreateApplication, useRegisterApplication } from './useApplications'

const DEFAULT_SCOPES = 'openid, profile, email, groups'

function splitList(value: string): string[] {
  return value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
}

/**
 * What this form holds: two of the fields are comma-separated text that becomes
 * an array on the way out, so the schema describes the typing rather than the
 * request. `registerApplicationRequest` checks the other end.
 *
 * The redirect rule is imported rather than restated. Restating it is how the
 * browser ends up permitting a wildcard the server refuses, which reads as the
 * server being broken at exactly the moment somebody is registering a client.
 */
const applicationForm = z
  .object({
    // Which kind this is. Not a detail: an application behind the proxy has no
    // redirect URIs, no scopes and no client id, so asking for them would be
    // asking for fields that do not apply to the commonest case.
    kind: z.enum(['proxy', 'oidc']),
    name: entityName,
    displayName: z.string().trim().max(200, 'At most 200 characters.'),
    redirects: z.string(),
    scopes: z.string(),
    confidential: z.boolean(),
    requireConsent: z.boolean(),
    devMode: z.boolean(),
  })
  // Checked on the object rather than per field, because whether these are
  // required depends on the kind — and a per-field rule cannot see it.
  .superRefine((values, ctx) => {
    if (values.kind !== 'oidc') return

    const parts = splitList(values.redirects)
    if (parts.length === 0) {
      ctx.addIssue({
        code: 'custom',
        path: ['redirects'],
        message: 'At least one — a client with none can never complete a login.',
      })
    }
    for (const part of parts) {
      const checked = redirectURI.safeParse(part)
      if (!checked.success) {
        // Named, because "one of these is wrong" in a comma-separated field
        // of four is not something anybody can act on.
        ctx.addIssue({
          code: 'custom',
          path: ['redirects'],
          message: `${part} — ${checked.error.issues[0]?.message ?? 'invalid'}`,
        })
      }
    }
    if (splitList(values.scopes).length === 0) {
      ctx.addIssue({ code: 'custom', path: ['scopes'], message: 'At least one scope.' })
    }
  })
type ApplicationForm = z.infer<typeof applicationForm>

const EMPTY: ApplicationForm = {
  kind: 'proxy',
  name: '',
  displayName: '',
  redirects: '',
  scopes: DEFAULT_SCOPES,
  confidential: false,
  requireConsent: false,
  devMode: false,
}

/**
 * Registering a relying party.
 *
 * The three switches are the whole security surface of this form, so each one
 * says what it means rather than restating its own name. Getting "confidential"
 * wrong ships a client secret to every user; getting "development mode" wrong
 * lets authorization codes cross the network in the clear.
 */
export function RegisterApplication() {
  const [open, setOpen] = useState(false)
  const [registered, setRegistered] = useState<RegisteredApplication | null>(null)

  const register = useRegisterApplication()
  const create = useCreateApplication()

  const form = useForm<ApplicationForm>({
    resolver: zodResolver(applicationForm),
    defaultValues: EMPTY,
  })

  const kind = form.watch('kind')

  function reset() {
    form.reset(EMPTY)
    setRegistered(null)
    register.reset()
    create.reset()
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) reset()
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">
          <PlusIcon />
          Register application
        </Button>
      </DialogTrigger>

      <DialogContent className="sm:max-w-lg">
        {registered === null ? (
          <>
            <DialogHeader>
              <DialogTitle>Register an application</DialogTitle>
              <DialogDescription>
                Creates a directory entity, which is what policy names — and an
                OIDC client registration too, if the application signs users in
                itself.
              </DialogDescription>
            </DialogHeader>

            <Form {...form}>
              <form
                className="space-y-4"
                onSubmit={(event) => {
                  void form.handleSubmit((values) => {
                    if (values.kind === 'proxy') {
                      // Nothing to show afterwards: there is no client id and no
                      // secret. The row appears in the list saying it has no
                      // hostname yet, which is the next thing to do.
                      create.mutate(
                        { name: values.name, displayName: values.displayName },
                        { onSuccess: () => { setOpen(false); reset() } },
                      )
                      return
                    }
                    register.mutate(
                      {
                        name: values.name,
                        displayName: values.displayName,
                        redirectUris: splitList(values.redirects),
                        scopes: splitList(values.scopes),
                        confidential: values.confidential,
                        requireConsent: values.requireConsent,
                        devMode: values.devMode,
                      },
                      { onSuccess: setRegistered },
                    )
                  })(event)
                }}
              >
                <FormField
                  control={form.control}
                  name="kind"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>What is it</FormLabel>
                      <FormControl>
                        <div className="grid gap-2 sm:grid-cols-2">
                          <KindChoice
                            selected={field.value === 'proxy'}
                            onSelect={() => { field.onChange('proxy') }}
                            title="Behind the proxy"
                            description="The proxy asks Cardinal on every request and the application implements nothing. Most internal applications."
                          />
                          <KindChoice
                            selected={field.value === 'oidc'}
                            onSelect={() => { field.onChange('oidc') }}
                            title="Signs users in itself"
                            description="OpenID Connect: the application runs its own login and owns its session."
                          />
                        </div>
                      </FormControl>
                      <FormDescription>
                        Both are directory entities and both are governed by
                        policy. This decides whether there is also an OIDC client
                        registration — which one it is can be changed later only
                        by registering again.
                      </FormDescription>
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Name</FormLabel>
                      <FormControl>
                        <Input placeholder="grafana" {...field} />
                      </FormControl>
                      <FormDescription>
                        Unique, and used in policy. Lower case, no spaces.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="displayName"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Display name</FormLabel>
                      <FormControl>
                        <Input placeholder="Grafana" {...field} />
                      </FormControl>
                      <FormDescription>Shown to users.</FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {kind === 'oidc' && (
                  <>
                    <FormField
                      control={form.control}
                      name="redirects"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Redirect URIs</FormLabel>
                          <FormControl>
                            <Input
                              placeholder="https://grafana.example.com/login/generic_oauth"
                              {...field}
                            />
                          </FormControl>
                          <FormDescription>
                            Comma-separated, exact matches. No wildcards — anyone
                            controlling a matching host could receive authorization
                            codes.
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="scopes"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Scopes</FormLabel>
                          <FormControl>
                            <Input {...field} />
                          </FormControl>
                          <FormDescription>Comma-separated.</FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="confidential"
                      render={({ field }) => (
                        <Toggle
                          label="Issue a client secret"
                          description="Only for applications running on a server that can keep one. A browser or mobile app cannot, and a secret shipped to every user is worse than none."
                          checked={field.value}
                          onChange={field.onChange}
                        />
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="requireConsent"
                      render={({ field }) => (
                        <Toggle
                          label="Ask the user for consent"
                          description="For third-party applications. A prompt in front of something your own organisation runs is one more thing people learn to dismiss unread."
                          checked={field.value}
                          onChange={field.onChange}
                        />
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="devMode"
                      render={({ field }) => (
                        <Toggle
                          label="Development mode"
                          description="Permits plain http redirect URIs, so authorization codes cross the network in the clear. Never in production."
                          checked={field.value}
                          onChange={field.onChange}
                          danger
                        />
                      )}
                    />
                  </>
                )}

                {kind === 'proxy' && (
                  <p className="text-sm text-muted-foreground">
                    Nothing else is needed here. Add the address it answers to
                    from its row afterwards — until it has one, forwardAuth
                    refuses every request to it.
                  </p>
                )}

                <ErrorMessage error={register.error ?? create.error} />

                <DialogFooter>
                  <Button type="submit" disabled={register.isPending || create.isPending}>
                    {register.isPending || create.isPending ? 'Registering…' : 'Register'}
                  </Button>
                </DialogFooter>
              </form>
            </Form>
          </>
        ) : (
          <Registered
            application={registered}
            onDone={() => { setOpen(false); reset() }}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

/**
 * The one moment the secret exists outside the database.
 *
 * Deliberately a separate step rather than a toast: closing this dialog is the
 * last chance to copy it, and that has to be obvious before it happens.
 */
function Registered({
  application,
  onDone,
}: {
  application: RegisteredApplication
  onDone: () => void
}) {
  return (
    <>
      <DialogHeader>
        <DialogTitle>{application.name} is registered</DialogTitle>
        <DialogDescription>
          Configure your application with these values.
        </DialogDescription>
      </DialogHeader>

      <div className="space-y-3">
        <Secret label="Client ID" value={application.clientId} />

        {application.secret === undefined ? (
          <p className="text-sm text-muted-foreground">
            A public client — no secret. It is protected by PKCE, which is
            required for every client Cardinal issues.
          </p>
        ) : (
          <>
            <Secret label="Client secret" value={application.secret} />
            <Alert variant="destructive">
              <TriangleAlertIcon />
              <AlertTitle>Copy the secret now</AlertTitle>
              <AlertDescription>
                Only its hash is stored, so this cannot be shown again. If you
                lose it, register the application afresh.
              </AlertDescription>
            </Alert>
          </>
        )}
      </div>

      <DialogFooter>
        <Button onClick={onDone}>Done</Button>
      </DialogFooter>
    </>
  )
}

function Secret({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)

  return (
    <div>
      <p className="text-sm font-medium">{label}</p>
      <div className="mt-1 flex gap-2">
        <code className="min-w-0 flex-1 truncate rounded-md border bg-muted px-3 py-2 font-mono text-xs">
          {value}
        </code>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            void navigator.clipboard.writeText(value).then(() => {
              setCopied(true)
            })
          }}
        >
          <CopyIcon />
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
    </div>
  )
}

/**
 * One of the two kinds, as a card rather than a dropdown.
 *
 * The choice decides which half of this form applies, and it is the one thing
 * on the page somebody unfamiliar with Cardinal has to get right — so it is
 * two visible options with their consequences written out, not a select whose
 * second entry nobody scrolls to.
 */
function KindChoice({
  selected,
  onSelect,
  title,
  description,
}: {
  selected: boolean
  onSelect: () => void
  title: string
  description: string
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={
        'rounded-md border p-3 text-left transition-colors ' +
        (selected ? 'border-primary bg-primary/5' : 'hover:bg-muted/50')
      }
    >
      <span className="block text-sm font-medium">{title}</span>
      <span className="mt-1 block text-xs text-muted-foreground">{description}</span>
    </button>
  )
}

function Toggle({
  label,
  description,
  checked,
  onChange,
  danger = false,
}: {
  label: string
  description: string
  checked: boolean
  onChange: (value: boolean) => void
  danger?: boolean
}) {
  return (
    <FormItem className="flex items-start gap-3 space-y-0">
      <FormControl>
        <Switch checked={checked} onCheckedChange={onChange} className="mt-0.5" />
      </FormControl>
      <div className="min-w-0 grid gap-1">
        <FormLabel>{label}</FormLabel>
        <FormDescription
          className={
            danger && checked ? 'text-xs text-destructive' : 'text-xs'
          }
        >
          {description}
        </FormDescription>
      </div>
    </FormItem>
  )
}
