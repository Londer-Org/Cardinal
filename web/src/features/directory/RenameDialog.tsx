import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { PencilIcon } from 'lucide-react'
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
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { ErrorMessage } from '@/components/ErrorMessage'
import { api, renameRequest, type RenameRequest } from '@/lib/api'

type Kind = 'users' | 'groups' | 'hosts'

/**
 * What each kind of rename actually changes downstream.
 *
 * Said per type because the consequences genuinely differ, and because "nothing
 * breaks" is the claim being made — a claim worth being specific about rather
 * than reassuring about.
 */
const CONSEQUENCES: Record<Kind, React.ReactNode> = {
  users: (
    <>
      Group membership, sessions, tokens, passkeys and every audit entry
      reference the account&apos;s identifier, not its name, so none of them
      notice. If they have a POSIX identity, hosts report the new name on their
      next refresh and the <strong>uid does not change</strong> — every file
      keeps its owner. The home directory keeps its old path, deliberately: the
      files are in it, and moving them would be the migration this design
      exists to avoid.
    </>
  ),
  groups: (
    <>
      Policy references groups by identifier, so no rule changes meaning. The
      name is what people search for and what appears in the groups claim
      applications receive — an application matching on the string rather than
      the identifier will stop matching.
    </>
  ),
  hosts: (
    <>
      The machine proves this name, so it must also be renamed wherever it is
      reached — DNS, inventory, the alias list here. Certificates already issued
      carry the old name until they expire, which is minutes. An alias is the
      better tool when both names should work.
    </>
  ),
}

const DESTINATION: Record<Kind, string> = {
  users: '/directory/people/$login',
  groups: '/directory/groups/$name',
  hosts: '/directory/hosts/$name',
}

/**
 * Renaming, which had no implementation anywhere.
 *
 * The README's first claim against LDAP is that the DN *is* the identity there,
 * so renaming breaks every reference — whereas here identity is an immutable
 * UUIDv7 and the name is an attribute. That was true of the schema and of
 * nothing else: no store method, no endpoint, no button.
 */
export function RenameDialog({ kind, current }: { kind: Kind; current: string }) {
  const [open, setOpen] = useState(false)
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const form = useForm<RenameRequest>({
    resolver: zodResolver(renameRequest),
    defaultValues: { name: current },
  })

  const rename = useMutation({
    mutationFn: (name: string) => api.directory.rename(kind, current, name),
    onSuccess: async (result) => {
      setOpen(false)
      // Everything keyed by the old name is now a 404, including the page this
      // dialog is on — so invalidate broadly and move to the new address
      // rather than leaving somebody looking at a name that no longer exists.
      await queryClient.invalidateQueries({ queryKey: ['directory'] })
      await navigate({
        to: DESTINATION[kind],
        params: kind === 'users' ? { login: result.name } : { name: result.name },
      })
    },
  })

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) {
          form.reset({ name: current })
          rename.reset()
        }
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" data-action="rename">
          <PencilIcon />
          Rename
        </Button>
      </DialogTrigger>

      <DialogContent>
        <DialogHeader>
          <DialogTitle>Rename {current}</DialogTitle>
          <DialogDescription>
            One column changes. The identifier stays, which is what makes this
            an edit rather than a migration.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form
            className="space-y-4"
            onSubmit={(event) => {
              void form.handleSubmit(({ name }) => { rename.mutate(name) })(event)
            }}
          >
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>New name</FormLabel>
                  <FormControl>
                    <Input {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <Alert>
              <AlertTitle>What follows the rename</AlertTitle>
              <AlertDescription>{CONSEQUENCES[kind]}</AlertDescription>
            </Alert>

            <ErrorMessage error={rename.error} />

            <DialogFooter>
              <Button type="submit" disabled={rename.isPending}>
                {rename.isPending ? 'Renaming…' : 'Rename'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
