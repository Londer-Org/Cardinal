import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { CopyIcon, LifeBuoyIcon, TriangleAlertIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
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
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import {
  openRecoveryRequest,
  type OpenRecoveryRequest,
  type RecoveryRequest,
} from '@/lib/api'
import {
  useApproveRecovery,
  useCancelRecovery,
  useOpenRecovery,
  useRecoveries,
} from './useRecovery'

/**
 * Requests to restore access to accounts that can already sign in.
 *
 * Issuing an enrollment link for such an account is account takeover by shape,
 * so it takes two administrators (ADR 0015). Listing the open requests matters
 * as much as making them: one nobody notices expires, and the person it
 * concerns stays locked out in the meantime.
 */
export function RecoveryRequests() {
  const { data: requests, isPending, error } = useRecoveries()
  const [issued, setIssued] = useState<string | null>(null)

  const items = requests ?? []

  return (
    <div className="space-y-4">
      {issued !== null && <IssuedLink url={issued} />}

      <Card>
        <CardHeader>
          <CardTitle>Open requests</CardTitle>
          <CardDescription>
            Two distinct administrators, neither of them the subject.
          </CardDescription>
          <CardAction>
            <OpenRequest />
          </CardAction>
        </CardHeader>

        <CardContent>
          <ErrorMessage error={error} />

          {isPending ? (
            <Skeleton className="h-16 w-full" />
          ) : items.length === 0 ? (
            <p className="py-2 text-sm text-muted-foreground">
              Nothing waiting. Ordinary onboarding does not appear here — only
              restoring an account that can already sign in.
            </p>
          ) : (
            <ul className="divide-y">
              {items.map((request) => (
                <RequestRow
                  key={request.subject}
                  request={request}
                  onIssued={setIssued}
                />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function RequestRow({
  request,
  onIssued,
}: {
  request: RecoveryRequest
  onIssued: (url: string) => void
}) {
  const approve = useApproveRecovery()
  const cancel = useCancelRecovery()

  const remaining = request.required - request.approvers.length

  return (
    <li className="space-y-2 py-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium">{request.subject}</p>
          <p className="text-xs text-muted-foreground">
            Asked by {request.requestedBy}
            {request.reason !== '' && ` · ${request.reason}`}
          </p>
        </div>
        <Badge variant="secondary" className="font-normal">
          {request.approvers.length} of {request.required}
        </Badge>
      </div>

      <p className="text-xs text-muted-foreground">
        {/* Naming them is the point: a second administrator deciding whether to
            approve is entitled to see who already has. */}
        Approved by {request.approvers.join(', ')} · expires{' '}
        {new Date(request.expiresAt).toLocaleString()}
      </p>

      <ErrorMessage error={approve.error ?? cancel.error} />

      <div className="flex gap-2">
        <Button
          size="sm"
          disabled={approve.isPending}
          onClick={() => {
            approve.mutate(request.subject, {
              onSuccess: (result) => {
                if (result.invitationUrl !== undefined) {
                  onIssued(result.invitationUrl)
                }
              },
            })
          }}
        >
          {approve.isPending
            ? 'Approving…'
            : remaining === 1
              ? 'Approve and issue link'
              : 'Approve'}
        </Button>
        <Button
          size="sm"
          variant="ghost"
          className="text-destructive"
          disabled={cancel.isPending}
          onClick={() => { cancel.mutate(request.subject) }}
        >
          Cancel request
        </Button>
      </div>
    </li>
  )
}

function IssuedLink({ url }: { url: string }) {
  const [copied, setCopied] = useState(false)

  return (
    <Alert>
      <TriangleAlertIcon />
      <AlertTitle>Recovery link issued — shown once</AlertTitle>
      <AlertDescription className="space-y-2">
        <p>
          Send it to the person whose access is being restored, and to nobody
          else. It lets whoever holds it register a passkey on that account.
        </p>
        <div className="flex w-full gap-2">
          <code className="min-w-0 flex-1 truncate rounded-md border bg-muted px-3 py-2 font-mono text-xs">
            {url}
          </code>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => {
              void navigator.clipboard.writeText(url).then(() => { setCopied(true) })
            }}
          >
            <CopyIcon />
            {copied ? 'Copied' : 'Copy'}
          </Button>
        </div>
      </AlertDescription>
    </Alert>
  )
}

function OpenRequest() {
  const [open, setOpen] = useState(false)
  const request = useOpenRecovery()

  const form = useForm<OpenRecoveryRequest>({
    resolver: zodResolver(openRecoveryRequest),
    defaultValues: { login: '', reason: '' },
  })

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) {
          form.reset()
          request.reset()
        }
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          <LifeBuoyIcon />
          Request recovery
        </Button>
      </DialogTrigger>

      <DialogContent>
        <DialogHeader>
          <DialogTitle>Request recovery</DialogTitle>
          <DialogDescription>
            Opens a request and counts as your approval. A second administrator
            has to agree before a link is issued.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form
            className="space-y-4"
            onSubmit={(event) => {
              void form.handleSubmit((values) => {
                request.mutate(values, { onSuccess: () => { setOpen(false) } })
              })(event)
            }}
          >
            <FormField
              control={form.control}
              name="login"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Account</FormLabel>
                  <FormControl>
                    <Input placeholder="jdoe" {...field} />
                  </FormControl>
                  <FormDescription>
                    Not your own — someone who can authenticate does not need
                    recovering.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="reason"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Why</FormLabel>
                  <FormControl>
                    <Input placeholder="Lost both keys · ticket 4412" {...field} />
                  </FormControl>
                  <FormDescription>
                    {/* The approver reads this and takes it on trust. Cardinal
                        cannot verify that someone really lost their laptop and
                        should not pretend to — the control is that a second
                        human is on the hook, not that the claim was checked. */}
                    The second administrator sees this when deciding.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <ErrorMessage error={request.error} />

            <DialogFooter>
              <Button type="submit" disabled={request.isPending}>
                {request.isPending ? 'Opening…' : 'Open request'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
