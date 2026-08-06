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
import type { CreatedUser } from '@/lib/api'
import { useCreateUser } from './useDirectory'

export function CreateUser() {
  const [open, setOpen] = useState(false)
  const [login, setLogin] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [invite, setInvite] = useState(true)
  const [created, setCreated] = useState<CreatedUser | null>(null)
  const create = useCreateUser()

  function reset() {
    setLogin('')
    setDisplayName('')
    setInvite(true)
    setCreated(null)
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
          Add person
        </Button>
      </DialogTrigger>

      <DialogContent className="sm:max-w-lg">
        {created === null ? (
          <>
            <DialogHeader>
              <DialogTitle>Add a person</DialogTitle>
              <DialogDescription>
                Creates the account. Nobody can sign in to it until a passkey is
                registered.
              </DialogDescription>
            </DialogHeader>

            <form
              className="space-y-4"
              onSubmit={(event) => {
                event.preventDefault()
                create.mutate(
                  {
                    login: login.trim(),
                    displayName: displayName.trim(),
                    invite,
                  },
                  { onSuccess: setCreated },
                )
              }}
            >
              <div className="space-y-1.5">
                <Label htmlFor="user-login">Username</Label>
                <Input
                  id="user-login"
                  value={login}
                  onChange={(event) => { setLogin(event.target.value) }}
                  placeholder="jdoe"
                  required
                />
                <p className="text-xs text-muted-foreground">
                  Appears in policy and in the audit trail. They cannot change it.
                </p>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="user-display">Name</Label>
                <Input
                  id="user-display"
                  value={displayName}
                  onChange={(event) => { setDisplayName(event.target.value) }}
                  placeholder="J Doe"
                />
                <p className="text-xs text-muted-foreground">
                  Optional — they set their own when they enrol.
                </p>
              </div>

              <div className="flex items-start gap-3">
                <Switch
                  id="user-invite"
                  checked={invite}
                  onCheckedChange={setInvite}
                  className="mt-0.5"
                />
                <div className="min-w-0">
                  <Label htmlFor="user-invite">Send an enrollment link</Label>
                  <p className="text-xs text-muted-foreground">
                    {/* On by default: an account created without one is an
                        account nobody can use, and the second step is the one
                        that gets forgotten. */}
                    Single use, expires in 24 hours. Without it the account
                    exists but nobody can sign in to it.
                  </p>
                </div>
              </div>

              <ErrorMessage error={create.error} />

              <DialogFooter>
                <Button type="submit" disabled={create.isPending}>
                  {create.isPending ? 'Creating…' : 'Create'}
                </Button>
              </DialogFooter>
            </form>
          </>
        ) : (
          <Created
            user={created}
            onDone={() => { setOpen(false); reset() }}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

function Created({ user, onDone }: { user: CreatedUser; onDone: () => void }) {
  const [copied, setCopied] = useState(false)

  return (
    <>
      <DialogHeader>
        <DialogTitle>{user.login} is ready</DialogTitle>
        <DialogDescription>
          {user.invitationUrl === undefined
            ? 'No enrollment link was issued — nobody can sign in to this account yet.'
            : 'Send this link however you like.'}
        </DialogDescription>
      </DialogHeader>

      {user.invitationUrl !== undefined && (
        <div className="space-y-3">
          <div className="flex gap-2">
            <code className="min-w-0 flex-1 truncate rounded-md border bg-muted px-3 py-2 font-mono text-xs">
              {user.invitationUrl}
            </code>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                const url = user.invitationUrl
                if (url === undefined) return
                void navigator.clipboard.writeText(url).then(() => {
                  setCopied(true)
                })
              }}
            >
              <CopyIcon />
              {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>

          <Alert>
            <TriangleAlertIcon />
            <AlertTitle>Shown once</AlertTitle>
            <AlertDescription>
              Only its hash is stored. If you lose it, issue another from the
              account — it supersedes this one.
            </AlertDescription>
          </Alert>
        </div>
      )}

      <DialogFooter>
        <Button onClick={onDone}>Done</Button>
      </DialogFooter>
    </>
  )
}
