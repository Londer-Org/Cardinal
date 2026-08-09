import { useState } from 'react'
import { PlusIcon, TriangleAlertIcon } from 'lucide-react'
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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import type { PolicyRule } from '@/lib/api'
import {
  useAddPolicyRule,
  usePolicyRules,
  useRemovePolicyRule,
} from './usePolicyRules'

/**
 * The live policy set, as rules rather than as text.
 *
 * The sentence policy exists to express is "these people may log into these
 * machines", and saying it used to mean editing a file and republishing it.
 * That is fine for a deployment keeping its policy in git and wrong for one
 * running the published image, where there is no file to edit at all.
 *
 * What this is not is a second representation. A rule composed here becomes
 * text in the same Cedar document, published as an ordinary version and rolled
 * back like any other — and everything the builder does not recognise travels
 * through untouched, comments included.
 */
export function PolicyRules() {
  const { data, isPending, error } = usePolicyRules()
  const [adding, setAdding] = useState(false)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Rules</CardTitle>
        <CardDescription>
          What the live set says, rule by rule. Adding or removing one publishes
          a new version and makes it live — the same operation as any other
          policy change, and undone the same way.
        </CardDescription>
        <CardAction>
          <Button size="sm" onClick={() => { setAdding(!adding) }}>
            <PlusIcon />
            Add a rule
          </Button>
        </CardAction>
      </CardHeader>

      <CardContent className="space-y-4">
        {error !== null && <ErrorMessage error={error} />}
        {adding && <AddRule onDone={() => { setAdding(false) }} />}

        {isPending || data === undefined ? (
          <div className="space-y-3">
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : (
          <ul className="divide-y">
            {data.rules.map((rule) => (
              <RuleRow key={rule.id} rule={rule} />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function RuleRow({ rule }: { rule: PolicyRule }) {
  const remove = useRemovePolicyRule()
  const [confirming, setConfirming] = useState(false)
  const [showing, setShowing] = useState(false)

  return (
    <li className="space-y-2 py-3">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <p className="truncate font-mono text-sm">{rule.id}</p>
          <p className="text-sm text-muted-foreground">{rule.summary}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {rule.composable ? (
            <Badge variant="secondary" className="font-normal">
              {rule.kind}
            </Badge>
          ) : (
            <Badge variant="outline">hand-written</Badge>
          )}
          <Button variant="ghost" size="sm" onClick={() => { setShowing(!showing) }}>
            {showing ? 'Hide' : 'Cedar'}
          </Button>
          {rule.composable && !confirming && (
            <Button
              variant="ghost"
              size="sm"
              className="text-destructive"
              onClick={() => { setConfirming(true) }}
            >
              Remove
            </Button>
          )}
        </div>
      </div>

      {rule.missing.length > 0 && (
        <Alert variant="destructive">
          <TriangleAlertIcon className="size-4" />
          <AlertTitle>This rule can never match</AlertTitle>
          <AlertDescription>
            It names {rule.missing.join(', ')}, which the directory does not
            have. Cedar is default-deny, so the rule refuses everybody — which
            looks exactly like it working.
          </AlertDescription>
        </Alert>
      )}

      {showing && (
        <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs">
          {rule.source}
        </pre>
      )}

      <ErrorMessage error={remove.error} />

      {confirming && (
        <div className="rounded-md border border-destructive/50 p-3">
          <p className="text-xs text-muted-foreground">
            {/* The consequence before the button. Cedar is default-deny, so
                removing a permit takes access away from everyone it reached. */}
            {rule.summary} — after this, nothing says so, and everyone it
            reached loses that access at the next request. A new version is
            published, so undoing it is one click in the list below.
          </p>
          <div className="mt-3 flex gap-2">
            <Button variant="outline" size="sm" onClick={() => { setConfirming(false) }}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              disabled={remove.isPending}
              onClick={() => { remove.mutate(rule.id) }}
            >
              {remove.isPending ? 'Removing…' : 'Remove'}
            </Button>
          </div>
        </div>
      )}
    </li>
  )
}

const KINDS = [
  { value: 'web-access' as const, title: 'Reach a site through the proxy' },
  { value: 'application-access' as const, title: 'Sign in to an application' },
  { value: 'ssh-login' as const, title: 'Log into machines over SSH' },
  { value: 'run-as-root' as const, title: 'Become root on machines' },
]

type RuleKind = (typeof KINDS)[number]['value']

/**
 * The rule as a sentence, before it exists.
 *
 * MIRRORS `describe` in internal/server/policy/rules.go, which writes the same
 * sentence into the comment above the composed rule. Two copies of a sentence
 * is a small cost against the thing this buys: the reason to compose a rule
 * rather than write Cedar is being able to read back what it will mean, and
 * reading it back after publishing is too late.
 */
function preview(
  kind: RuleKind,
  group: string,
  resourceGroup: string,
  application: string,
  accounts: string,
): string {
  const who = group.trim() === '' ? 'Anyone who signs in' : `Members of ${group.trim()}`

  const target =
    application.trim() !== ''
      ? application.trim()
      : resourceGroup.trim() !== ''
        ? `anything in ${resourceGroup.trim()}`
        : '…'

  if (kind === 'ssh-login') {
    const named = accounts
      .split(',')
      .map((a) => a.trim())
      .filter((a) => a !== '')
    const as = named.length === 0 ? 'their own account' : named.join(' or ')
    return `${who} may log into ${target}, as ${as}.`
  }
  if (kind === 'run-as-root') return `${who} may become root on ${target}.`
  if (kind === 'application-access') return `${who} may sign in to ${target}.`
  return `${who} may reach ${target}.`
}

/**
 * Composing one rule.
 *
 * Groups and applications are typed by name and resolved server-side, so a
 * rename cannot change what a stored rule means and nobody has to copy a UUID
 * between two pages. The sentence under the form is what the rule will say, and
 * it is shown before the button rather than after: the whole reason to compose
 * a rule rather than write Cedar is being able to read it back.
 */
function AddRule({ onDone }: { onDone: () => void }) {
  const add = useAddPolicyRule()

  const [kind, setKind] = useState<RuleKind>('web-access')
  const [id, setID] = useState('')
  const [principalGroup, setPrincipalGroup] = useState('')
  const [resourceGroup, setResourceGroup] = useState('')
  const [resourceApplication, setResourceApplication] = useState('')
  const [accounts, setAccounts] = useState('')

  const isHostRule = kind === 'ssh-login' || kind === 'run-as-root'

  return (
    <form
      className="space-y-4 rounded-md border p-4"
      onSubmit={(event) => {
        event.preventDefault()
        add.mutate(
          {
            id,
            kind,
            principalGroup,
            resourceGroup,
            resourceApplication: isHostRule ? '' : resourceApplication,
            anything: false,
            localAccounts: accounts
              .split(',')
              .map((a) => a.trim())
              .filter((a) => a !== ''),
          },
          { onSuccess: onDone },
        )
      }}
    >
      <div className="grid gap-2 sm:grid-cols-2">
        {KINDS.map((option) => (
          <button
            key={option.value}
            type="button"
            aria-pressed={kind === option.value}
            onClick={() => { setKind(option.value) }}
            className={
              'rounded-md border p-3 text-left text-sm transition-colors ' +
              (kind === option.value ? 'border-primary bg-primary/5' : 'hover:bg-muted/50')
            }
          >
            {option.title}
          </button>
        ))}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="rule-id">Name</Label>
          <Input
            id="rule-id"
            value={id}
            placeholder="sre-may-reach-grafana"
            onChange={(event) => { setID(event.target.value) }}
          />
          <p className="text-xs text-muted-foreground">
            What the decision log will call it when this rule decides something.
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="rule-group">Group</Label>
          <Input
            id="rule-group"
            value={principalGroup}
            placeholder="sre"
            onChange={(event) => { setPrincipalGroup(event.target.value) }}
          />
          <p className="text-xs text-muted-foreground">
            Leave blank for anyone who signs in.
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="rule-resource">
            {isHostRule ? 'Host group' : 'Application group'}
          </Label>
          <Input
            id="rule-resource"
            value={resourceGroup}
            placeholder={isHostRule ? 'env-prod' : 'staff-apps'}
            onChange={(event) => { setResourceGroup(event.target.value) }}
          />
        </div>

        {!isHostRule && (
          <div className="space-y-2">
            <Label htmlFor="rule-app">…or one application</Label>
            <Input
              id="rule-app"
              value={resourceApplication}
              placeholder="grafana"
              onChange={(event) => { setResourceApplication(event.target.value) }}
            />
          </div>
        )}

        {kind === 'ssh-login' && (
          <div className="space-y-2">
            <Label htmlFor="rule-accounts">Local accounts</Label>
            <Input
              id="rule-accounts"
              value={accounts}
              placeholder="deploy, www-data"
              onChange={(event) => { setAccounts(event.target.value) }}
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated. Blank means their own login, which is the usual
              answer. Never root — becoming root is a separate rule with a
              stricter freshness requirement.
            </p>
          </div>
        )}
      </div>

      <p className="rounded-md bg-muted px-3 py-2 text-sm">
        {preview(kind, principalGroup, resourceGroup, resourceApplication, accounts)}
      </p>

      <ErrorMessage error={add.error} />

      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={add.isPending || id === ''}>
          {add.isPending ? 'Publishing…' : 'Add and make live'}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={onDone}>
          Cancel
        </Button>
      </div>
    </form>
  )
}
