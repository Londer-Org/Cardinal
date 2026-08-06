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
  const [owner, setOwner] = useState('')
  const create = useCreateGroup()

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) {
          setName('')
          setDisplayName('')
          setOwner('')
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
            Groups are what policy references, so the name matters. A group
            created here never confers authority inside Cardinal — that is a
            decision the policy set makes.
          </DialogDescription>
        </DialogHeader>

        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            create.mutate(
              {
                name: name.trim(),
                displayName: displayName.trim(),
                owner: owner.trim(),
              },
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

          <div className="space-y-1.5">
            <Label htmlFor="group-owner">For an application</Label>
            <Input
              id="group-owner"
              value={owner}
              onChange={(event) => { setOwner(event.target.value) }}
              placeholder="aura"
            />
            <p className="text-xs text-muted-foreground">
              {/* Organisational only. Cardinal treats an owned group exactly
                  like any other and still sends it in the groups claim — this
                  records who it is for, so `aura-users` sits beside `aura`
                  rather than in a flat list. */}
              Optional. Groups like <code>aura-users</code> exist for one
              application; naming it here keeps them together. Cardinal treats
              them like any other group.
            </p>
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
