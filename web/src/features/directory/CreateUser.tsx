import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
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
import { createUserRequest, type CreatedUser, type CreateUserRequest } from '@/lib/api'
import { useCreateUser } from './useDirectory'

// Invite on by default: an account created without one is an account nobody
// can use, and issuing it is the step that gets forgotten.
const EMPTY: CreateUserRequest = { login: '', displayName: '', invite: true }

export function CreateUser() {
  const [open, setOpen] = useState(false)
  const [created, setCreated] = useState<CreatedUser | null>(null)
  const create = useCreateUser()

  const form = useForm<CreateUserRequest>({
    resolver: zodResolver(createUserRequest),
    defaultValues: EMPTY,
  })

  function reset() {
    form.reset(EMPTY)
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

            <Form {...form}>
              <form
                className="space-y-4"
                onSubmit={(event) => {
                  void form.handleSubmit((values) => {
                    create.mutate(values, { onSuccess: setCreated })
                  })(event)
                }}
              >
                <FormField
                  control={form.control}
                  name="login"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Username</FormLabel>
                      <FormControl>
                        <Input placeholder="jdoe" {...field} />
                      </FormControl>
                      <FormDescription>
                        Appears in policy and in the audit trail. They cannot
                        change it.
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
                      <FormLabel>Name</FormLabel>
                      <FormControl>
                        <Input placeholder="J Doe" {...field} />
                      </FormControl>
                      <FormDescription>
                        Optional — they set their own when they enrol.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="invite"
                  render={({ field }) => (
                    <FormItem className="flex items-start gap-3 space-y-0">
                      <FormControl>
                        <Switch
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          className="mt-0.5"
                        />
                      </FormControl>
                      <div className="min-w-0 grid gap-1">
                        <FormLabel>Send an enrollment link</FormLabel>
                        <FormDescription>
                          Single use, expires in 24 hours. Without it the
                          account exists but nobody can sign in to it.
                        </FormDescription>
                      </div>
                    </FormItem>
                  )}
                />

                <ErrorMessage error={create.error} />

                <DialogFooter>
                  <Button type="submit" disabled={create.isPending}>
                    {create.isPending ? 'Creating…' : 'Create'}
                  </Button>
                </DialogFooter>
              </form>
            </Form>
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
