import { useState } from 'react'
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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { ErrorMessage } from '@/components/ErrorMessage'
import type { RegisteredApplication } from '@/lib/api'
import { useRegisterApplication } from './useApplications'

const DEFAULT_SCOPES = 'openid, profile, email, groups'

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

  const [name, setName] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [redirects, setRedirects] = useState('')
  const [scopes, setScopes] = useState(DEFAULT_SCOPES)
  const [confidential, setConfidential] = useState(false)
  const [requireConsent, setRequireConsent] = useState(false)
  const [devMode, setDevMode] = useState(false)

  const register = useRegisterApplication()

  function reset() {
    setName('')
    setDisplayName('')
    setRedirects('')
    setScopes(DEFAULT_SCOPES)
    setConfidential(false)
    setRequireConsent(false)
    setDevMode(false)
    setRegistered(null)
    register.reset()
  }

  function submit() {
    register.mutate(
      {
        name: name.trim(),
        displayName: displayName.trim(),
        redirectUris: splitList(redirects),
        scopes: splitList(scopes),
        confidential,
        requireConsent,
        devMode,
      },
      { onSuccess: setRegistered },
    )
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
                Creates a directory entity and an OIDC client registration.
              </DialogDescription>
            </DialogHeader>

            <form
              className="space-y-4"
              onSubmit={(event) => {
                event.preventDefault()
                submit()
              }}
            >
              <Field
                id="app-name"
                label="Name"
                hint="Unique, and used in policy. Lower case, no spaces."
              >
                <Input
                  id="app-name"
                  value={name}
                  onChange={(event) => { setName(event.target.value) }}
                  placeholder="grafana"
                  required
                />
              </Field>

              <Field id="app-display" label="Display name" hint="Shown to users.">
                <Input
                  id="app-display"
                  value={displayName}
                  onChange={(event) => { setDisplayName(event.target.value) }}
                  placeholder="Grafana"
                />
              </Field>

              <Field
                id="app-redirects"
                label="Redirect URIs"
                hint="Comma-separated, exact matches. No wildcards — anyone controlling a matching host could receive authorization codes."
              >
                <Input
                  id="app-redirects"
                  value={redirects}
                  onChange={(event) => { setRedirects(event.target.value) }}
                  placeholder="https://grafana.example.com/login/generic_oauth"
                  required
                />
              </Field>

              <Field id="app-scopes" label="Scopes" hint="Comma-separated.">
                <Input
                  id="app-scopes"
                  value={scopes}
                  onChange={(event) => { setScopes(event.target.value) }}
                />
              </Field>

              <Toggle
                id="app-confidential"
                label="Issue a client secret"
                description="Only for applications running on a server that can keep one. A browser or mobile app cannot, and a secret shipped to every user is worse than none."
                checked={confidential}
                onChange={setConfidential}
              />

              <Toggle
                id="app-consent"
                label="Ask the user for consent"
                description="For third-party applications. A prompt in front of something your own organisation runs is one more thing people learn to dismiss unread."
                checked={requireConsent}
                onChange={setRequireConsent}
              />

              <Toggle
                id="app-dev"
                label="Development mode"
                description="Permits plain http redirect URIs, so authorization codes cross the network in the clear. Never in production."
                checked={devMode}
                onChange={setDevMode}
                danger
              />

              <ErrorMessage error={register.error} />

              <DialogFooter>
                <Button type="submit" disabled={register.isPending}>
                  {register.isPending ? 'Registering…' : 'Register'}
                </Button>
              </DialogFooter>
            </form>
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

function Field({
  id,
  label,
  hint,
  children,
}: {
  id: string
  label: string
  hint: string
  children: React.ReactNode
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      <p className="text-xs text-muted-foreground">{hint}</p>
    </div>
  )
}

function Toggle({
  id,
  label,
  description,
  checked,
  onChange,
  danger = false,
}: {
  id: string
  label: string
  description: string
  checked: boolean
  onChange: (value: boolean) => void
  danger?: boolean
}) {
  return (
    <div className="flex items-start gap-3">
      <Switch id={id} checked={checked} onCheckedChange={onChange} className="mt-0.5" />
      <div className="min-w-0">
        <Label htmlFor={id}>{label}</Label>
        <p
          className={
            danger && checked
              ? 'text-xs text-destructive'
              : 'text-xs text-muted-foreground'
          }
        >
          {description}
        </p>
      </div>
    </div>
  )
}

function splitList(value: string): string[] {
  return value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
}
