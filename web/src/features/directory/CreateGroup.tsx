import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
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
import { ErrorMessage } from '@/components/ErrorMessage'
import { createGroupRequest, type CreateGroupRequest } from '@/lib/api'
import { ApplicationPicker } from './ApplicationPicker'
import { useCreateGroup } from './useDirectory'

const EMPTY: CreateGroupRequest = { name: '', displayName: '', owner: '' }

export function CreateGroup() {
  const [open, setOpen] = useState(false)
  const create = useCreateGroup()

  const form = useForm<CreateGroupRequest>({
    resolver: zodResolver(createGroupRequest),
    defaultValues: EMPTY,
  })

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) {
          form.reset(EMPTY)
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

        <Form {...form}>
          <form
            className="space-y-4"
            onSubmit={(event) => {
              void form.handleSubmit((values) => {
                create.mutate(values, { onSuccess: () => { setOpen(false) } })
              })(event)
            }}
          >
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <Input placeholder="engineers" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="displayName"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <Input placeholder="Engineering" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="owner"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>For an application</FormLabel>
                  <ApplicationPicker
                    id={`${field.name}-picker`}
                    value={field.value}
                    onChange={field.onChange}
                  />
                  <FormDescription>
                    {/* Organisational only. Cardinal treats an owned group
                        exactly like any other and still sends it in the groups
                        claim — this records who it is for, so `aura-users` sits
                        beside `aura` rather than in a flat list. */}
                    Optional. Groups like <code>aura-users</code> exist for one
                    application; naming it here keeps them together. Cardinal
                    treats them like any other group.
                  </FormDescription>
                  <FormMessage />
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
      </DialogContent>
    </Dialog>
  )
}
