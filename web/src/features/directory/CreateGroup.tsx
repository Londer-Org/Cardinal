import { useState } from 'react'
import { PlusIcon } from 'lucide-react'
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
import { ErrorMessage } from '@/components/ErrorMessage'
import { useCreateGroup } from './useDirectory'

export function CreateGroup() {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [displayName, setDisplayName] = useState('')
  const create = useCreateGroup()

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) {
          setName('')
          setDisplayName('')
          create.reset()
        }
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          <PlusIcon />
          New group
        </Button>
      </DialogTrigger>

      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create a group</DialogTitle>
          <DialogDescription>
            Groups are what policy references, so the name matters.
          </DialogDescription>
        </DialogHeader>

        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            create.mutate(
              { name: name.trim(), displayName: displayName.trim() },
              { onSuccess: () => { setOpen(false) } },
            )
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="group-name">Name</Label>
            <Input
              id="group-name"
              value={name}
              onChange={(event) => { setName(event.target.value) }}
              placeholder="engineers"
              required
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="group-display">Description</Label>
            <Input
              id="group-display"
              value={displayName}
              onChange={(event) => { setDisplayName(event.target.value) }}
              placeholder="Engineering"
            />
          </div>

          <ErrorMessage error={create.error} />

          <DialogFooter>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? 'Creating…' : 'Create'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
