import { useState } from 'react'
import { CheckIcon, ShieldOffIcon, XIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import type { Decision } from '@/lib/api'
import { extractPolicy, useDecisions, usePolicy } from './useDecisions'

/**
 * "Why was I denied?"
 *
 * The question neither FreeIPA nor Keycloak can answer without a human reading
 * three separate configurations. Every decision here names the rule that made
 * it, and clicking through shows that rule's text — so the answer is not merely
 * "denied" but "denied by this, which says this".
 */
export function DecisionExplorer() {
  const [deniedOnly, setDeniedOnly] = useState(false)
  const [inspecting, setInspecting] = useState<string | null>(null)

  const { data: decisions, isPending, error } = useDecisions(deniedOnly)
  const { data: policy } = usePolicy()

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle>Access decisions</CardTitle>
            <CardDescription>
              Every authorization decision, and the rule that made it.
              {policy && ` Policy version ${policy.version}.`}
            </CardDescription>
          </div>
          <Button
            variant={deniedOnly ? 'default' : 'outline'}
            size="sm"
            onClick={() => { setDeniedOnly(!deniedOnly) }}
          >
            <ShieldOffIcon />
            Denied only
          </Button>
        </div>
      </CardHeader>

      <CardContent>
        {isPending ? (
          <div className="space-y-2">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
          </div>
        ) : !decisions || decisions.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">
            {deniedOnly
              ? 'Nothing has been denied.'
              : 'No decisions yet. Visit a protected application to generate some.'}
          </p>
        ) : (
          <ul className="divide-y">
            {decisions.map((decision, index) => (
              <DecisionRow
                // The API returns no stable id, so position plus resource is
                // the best available key. Acceptable because the list is
                // append-only and ordered.
                key={`${String(index)}-${decision.resource}`}
                decision={decision}
                onInspect={setInspecting}
              />
            ))}
          </ul>
        )}

        <ErrorMessage error={error} />
      </CardContent>

      <PolicyDialog
        name={inspecting}
        document={policy?.document ?? ''}
        onClose={() => { setInspecting(null) }}
      />
    </Card>
  )
}

function DecisionRow({
  decision,
  onInspect,
}: {
  decision: Decision
  onInspect: (name: string) => void
}) {
  return (
    <li className="flex items-start gap-3 py-3">
      <div
        className={`mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full ${
          decision.allowed
            ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400'
            : 'bg-destructive/10 text-destructive'
        }`}
        aria-label={decision.allowed ? 'Allowed' : 'Denied'}
      >
        {decision.allowed ? <CheckIcon className="size-3" /> : <XIcon className="size-3" />}
      </div>

      <div className="min-w-0 flex-1">
        <p className="truncate font-mono text-sm">{decision.resource}</p>
        <p className="mt-0.5 text-sm text-muted-foreground">{decision.explanation}</p>

        {/* The reasons are the point of the whole feature, so they are
            clickable rather than decorative: seeing the rule is what lets
            someone judge whether the rule is right. */}
        {decision.reasons.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {decision.reasons.map((name) => (
              <button key={name} type="button" onClick={() => { onInspect(name) }}>
                <Badge
                  variant="secondary"
                  className="cursor-pointer font-mono text-xs hover:bg-accent"
                >
                  {name}
                </Badge>
              </button>
            ))}
          </div>
        )}

        {decision.errors.length > 0 && (
          <p className="mt-1.5 text-xs text-destructive">
            Policy evaluation errors: {decision.errors.join('; ')}
          </p>
        )}
      </div>

      <div className="shrink-0 text-right text-xs text-muted-foreground">
        <div>{decision.decisionPoint}</div>
        <div>{decision.durationMs.toFixed(2)} ms</div>
      </div>
    </li>
  )
}

function PolicyDialog({
  name,
  document,
  onClose,
}: {
  name: string | null
  document: string
  onClose: () => void
}) {
  const source = name === null ? null : extractPolicy(document, name)

  return (
    <Dialog open={name !== null} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="font-mono text-base">{name}</DialogTitle>
          <DialogDescription>
            The rule as written. Policies live in git and are versioned; this is
            the text of the version that decided.
          </DialogDescription>
        </DialogHeader>

        {source === null ? (
          <p className="text-sm text-muted-foreground">
            This rule is not in the active policy set — the decision was made by
            an earlier version.
          </p>
        ) : (
          <pre className="overflow-x-auto rounded-md border bg-muted p-4 text-xs">
            <code>{source}</code>
          </pre>
        )}
      </DialogContent>
    </Dialog>
  )
}
