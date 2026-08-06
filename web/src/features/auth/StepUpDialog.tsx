import { useEffect, useState } from 'react'
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
import { useStepUp } from './useStepUp'

/**
 * Asks for the security key when something a user did was refused.
 *
 * Only then. Arriving at an administrative page with a stale session is handled
 * by the page itself (see RequiresFreshAuth), because interrupting somebody
 * with a modal for navigating where they meant to go is a poor trade — they
 * already know where they are, and the page can say what it needs without
 * taking the screen.
 *
 * This is for the other case: you pressed something and it did not happen. A
 * dialog is right there, because an action failing silently is worse than being
 * asked.
 *
 * Cancelling is safe for the same reason. You are on a page that works, doing
 * something you can do again — there is nothing to be stranded on. That was not
 * true of the earlier "Not now", which left an empty table under the words
 * "Nobody yet.", a statement about the directory rather than about the refusal,
 * and a false one.
 *
 * Deliberately does not replay the refused request. Re-running a mutation
 * nobody re-confirmed is how something gets granted twice; reads come back on
 * their own because the queries are invalidated.
 */
export function StepUpDialog() {
  const [open, setOpen] = useState(false)
  const stepUp = useStepUp()

  useEffect(() => onStepUpNeeded(() => { setOpen(true) }), [])

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) stepUp.reset()
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Confirm it is you</DialogTitle>
          <DialogDescription>
            That needs a security key used in the last five minutes. Your
            session is fine — this only re-proves the key, and you stay where
            you are.
          </DialogDescription>
        </DialogHeader>

        <ErrorMessage error={stepUp.error} />

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => { setOpen(false) }}
            disabled={stepUp.isPending}
          >
            Cancel
          </Button>
          <Button
            disabled={stepUp.isPending}
            onClick={() => {
              stepUp.mutate(undefined, {
                onSuccess: () => { setOpen(false) },
              })
            }}
          >
            <KeyRoundIcon />
            {stepUp.isPending ? 'Waiting for your device…' : 'Use my security key'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
