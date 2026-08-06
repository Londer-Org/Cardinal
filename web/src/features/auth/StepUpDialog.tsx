import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { KeyRoundIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { ErrorMessage } from '@/components/ErrorMessage'
import { onStepUpNeeded } from '@/lib/api'
import { useReAuth } from './useReAuth'

/**
 * Asks for the security key where the user already is.
 *
 * Policy can demand a device-bound credential used in the last five minutes.
 * What used to happen when it did: the section quietly emptied, and getting it
 * back meant working out that Passkeys was the place to go and signing in
 * again — a puzzle presented as a blank page, mid-task.
 *
 * Now any refusal for want of freshness opens this. Touch the key and the page
 * repopulates where it stood.
 *
 * Deliberately does not replay the request that was refused. Re-running a
 * mutation nobody re-confirmed is how something gets granted twice; reads come
 * back on their own because the queries are invalidated.
 */
export function StepUpDialog() {
  const [open, setOpen] = useState(false)
  const reauth = useReAuth()
  const queryClient = useQueryClient()

  useEffect(() => onStepUpNeeded(() => { setOpen(true) }), [])

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) reauth.reset()
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Confirm it is you</DialogTitle>
          <DialogDescription>
            Changing who can reach what needs a security key used in the last
            five minutes. Your session stays as it is — this only re-proves the
            key.
          </DialogDescription>
        </DialogHeader>

        <ErrorMessage error={reauth.error} />

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => { setOpen(false) }}
            disabled={reauth.isPending}
          >
            Not now
          </Button>
          <Button
            disabled={reauth.isPending}
            onClick={() => {
              reauth.mutate(undefined, {
                onSuccess: () => {
                  setOpen(false)
                  // Everything the page was refused, asked again. The user is
                  // left looking at the screen they were on, populated.
                  void queryClient.invalidateQueries()
                },
              })
            }}
          >
            <KeyRoundIcon />
            {reauth.isPending ? 'Waiting for your device…' : 'Use my security key'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
