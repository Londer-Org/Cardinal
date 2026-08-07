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
import { createHostRequest, type CreateHostRequest } from '@/lib/api'
import { useCreateHost } from './useDirectory'

const EMPTY: CreateHostRequest = { name: '', displayName: '' }

/**
 * Adding a machine to the directory.
 *
 * Creates the record and nothing else — the machine still cannot prove it is
 * this host until it enrols, which is a second step on the host's own page. The
 * two are deliberately separate: the token has a short life and is shown once,
 * so issuing it at creation would mean losing it whenever somebody adds a
 * machine before they are ready to configure it.
 */
export function CreateHost() {
  const [open, setOpen] = useState(false)
  const create = useCreateHost()

  const form = useForm<CreateHostRequest>({
    resolver: zodResolver(createHostRequest),
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
        <Button size="sm">
          <PlusIcon />
          Add host
        </Button>
      </DialogTrigger>

      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add a host</DialogTitle>
          <DialogDescription>
            Creates the directory record. Enrol the machine afterwards from its
            own page — until then nothing can log into it through Cardinal.
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
                    <Input placeholder="web-01.prod" {...field} />
                  </FormControl>
                  <FormDescription>
                    What policy matches on, and the name the machine proves it
                    holds. Additional names can be granted later.
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
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <Input placeholder="Production web server" {...field} />
                  </FormControl>
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
