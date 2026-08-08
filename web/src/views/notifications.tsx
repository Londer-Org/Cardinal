import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Mail, RotateCcw } from 'lucide-react'
import { api, queryKeys, type MailSettings, type MailTemplate } from '@/lib/api'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { ViewHeader } from '@/views/ViewHeader'

/**
 * Notification email.
 *
 * Here rather than in the configuration file because a deployment running the
 * published image cannot edit files inside it — the same reason the CLI has
 * `cardinal mail set`. Which of the two you use depends on whether anybody can
 * sign in yet.
 *
 * Nothing sent from here authorises anything (ADR 0009): these messages report
 * what happened to an account, so a compromised mail server reads news rather
 * than gaining access.
 */
export function NotificationsView() {
  const { data, isPending } = useQuery({
    queryKey: queryKeys.mail(),
    queryFn: () => api.mail.settings(),
  })

  if (isPending) return <Skeleton className="h-96 w-full" />

  return (
    <div className="space-y-8">
      <ViewHeader
        title="Notification email"
        description="Telling people what happened to their account. Nothing here grants access."
      />
      {data && <SettingsForm settings={data} />}
      <Templates />
    </div>
  )
}

function SettingsForm({ settings }: { settings: MailSettings }) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ ...settings, password: '' })
  const [testTo, setTestTo] = useState('')
  const [testResult, setTestResult] = useState<{
    sent: boolean
    error?: string | undefined
  } | null>(null)

  const save = useMutation({
    mutationFn: () => api.mail.save(form),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.mail() }),
  })

  const test = useMutation({
    mutationFn: () => api.mail.test(testTo),
    onSuccess: (result) => {
      setTestResult(result)
    },
  })

  return (
    <section className="max-w-2xl space-y-4">
      <div className="flex items-center gap-2">
        <h2 className="font-semibold">Relay</h2>
        {settings.enabled ? (
          <Badge variant="secondary">sending</Badge>
        ) : (
          <Badge variant="outline">off</Badge>
        )}
      </div>

      {settings.failing > 0 && (
        <Alert variant="destructive">
          <AlertTriangle className="size-4" />
          <AlertTitle>
            {settings.failing} of {settings.queued} queued messages are failing
          </AlertTitle>
          <AlertDescription>
            They have been tried more than three times. Send a test below — the
            relay&rsquo;s own answer usually says why.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Host" value={form.host} onChange={(v) => { setForm({ ...form, host: v }) }} />
        <Field
          label="Port"
          value={String(form.port)}
          onChange={(v) => { setForm({ ...form, port: Number(v) || 0 }) }}
        />
        <Field
          label="Username"
          value={form.username}
          onChange={(v) => { setForm({ ...form, username: v }) }}
        />
        <div className="space-y-2">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            type="password"
            placeholder={settings.passwordSet ? 'unchanged' : 'none'}
            value={form.password}
            onChange={(e) => { setForm({ ...form, password: e.target.value }) }}
          />
          <p className="text-xs text-muted-foreground">
            Write-only. Leave blank to keep the stored one.
          </p>
        </div>
        <Field
          label="From address"
          value={form.fromAddress}
          onChange={(v) => { setForm({ ...form, fromAddress: v }) }}
        />
        <Field
          label="From name"
          value={form.fromName}
          onChange={(v) => { setForm({ ...form, fromName: v }) }}
        />
        <Field
          label="Reply-to"
          value={form.replyTo}
          onChange={(v) => { setForm({ ...form, replyTo: v }) }}
        />
        <div className="space-y-2">
          <Label htmlFor="tls">Transport security</Label>
          <select
            id="tls"
            className="h-9 w-full rounded-md border bg-background px-3 text-sm"
            value={form.tlsMode}
            onChange={(e) => {
              setForm({ ...form, tlsMode: e.target.value as typeof form.tlsMode })
            }}
          >
            <option value="starttls">STARTTLS (required)</option>
            <option value="tls">TLS from the start</option>
            <option value="none">None — local relay only</option>
          </select>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <Switch
          id="enabled"
          checked={form.enabled}
          onCheckedChange={(on) => { setForm({ ...form, enabled: on }) }}
        />
        <Label htmlFor="enabled">Send notifications</Label>
      </div>

      <div className="flex gap-3">
        <Button onClick={() => { save.mutate() }} disabled={save.isPending}>
          {save.isPending ? 'Saving…' : 'Save'}
        </Button>
      </div>

      <div className="space-y-2 rounded-lg border p-4">
        <h3 className="flex items-center gap-2 text-sm font-semibold">
          <Mail className="size-4" />
          Send a test
        </h3>
        <p className="text-xs text-muted-foreground">
          Sent immediately rather than queued, and the relay&rsquo;s exact answer
          is shown — which is usually the whole diagnosis.
        </p>
        <div className="flex gap-2">
          <Input
            placeholder="you@example.com"
            value={testTo}
            onChange={(e) => { setTestTo(e.target.value) }}
          />
          <Button
            variant="outline"
            onClick={() => { test.mutate() }}
            disabled={test.isPending || !testTo}
          >
            Send
          </Button>
        </div>
        {testResult?.sent && (
          <Alert>
            <CheckCircle2 className="size-4" />
            <AlertDescription>Sent. Check that mailbox.</AlertDescription>
          </Alert>
        )}
        {testResult && !testResult.sent && (
          <Alert variant="destructive">
            <AlertTriangle className="size-4" />
            <AlertDescription className="font-mono text-xs">
              {testResult.error}
            </AlertDescription>
          </Alert>
        )}
      </div>
    </section>
  )
}

function Templates() {
  const queryClient = useQueryClient()
  const { data } = useQuery({
    queryKey: queryKeys.mailTemplates(),
    queryFn: () => api.mail.templates(),
  })
  const [editing, setEditing] = useState<string | null>(null)

  const reset = useMutation({
    mutationFn: (kind: string) => api.mail.resetTemplate(kind),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.mailTemplates() }),
  })

  if (!data) return null

  return (
    <section className="max-w-3xl space-y-4">
      <div>
        <h2 className="font-semibold">Messages</h2>
        <p className="text-sm text-muted-foreground">
          Reword any of these. Every message keeps a footer naming this system
          and the account it concerns, which cannot be edited away — without it a
          template could be turned into something indistinguishable from a
          phishing mail, sent from your own relay.
        </p>
      </div>

      <div className="space-y-2">
        {data.templates.map((t) => (
          <TemplateRow
            key={t.kind}
            template={t}
            open={editing === t.kind}
            onToggle={() => { setEditing(editing === t.kind ? null : t.kind) }}
            onReset={() => { reset.mutate(t.kind) }}
          />
        ))}
      </div>
    </section>
  )
}

function TemplateRow({
  template,
  open,
  onToggle,
  onReset,
}: {
  template: MailTemplate
  open: boolean
  onToggle: () => void
  onReset: () => void
}) {
  const queryClient = useQueryClient()
  const [subject, setSubject] = useState(template.subject)
  const [body, setBody] = useState(template.body)
  const [error, setError] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () => api.mail.saveTemplate(template.kind, subject, body),
    onSuccess: () => {
      setError(null)
      return queryClient.invalidateQueries({ queryKey: queryKeys.mailTemplates() })
    },
    onError: (err: Error) => {
      setError(err.message)
    },
  })

  return (
    <div className="rounded-lg border">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center justify-between px-4 py-3 text-left text-sm"
      >
        <span className="font-mono">{template.kind}</span>
        {template.overridden ? (
          <Badge variant="secondary">reworded</Badge>
        ) : (
          <Badge variant="outline">as shipped</Badge>
        )}
      </button>

      {open && (
        <div className="space-y-3 border-t p-4">
          <div className="space-y-2">
            <Label>Subject</Label>
            <Input value={subject} onChange={(e) => { setSubject(e.target.value) }} />
          </div>
          <div className="space-y-2">
            <Label>Body</Label>
            <Textarea
              rows={10}
              className="font-mono text-xs"
              value={body}
              onChange={(e) => { setBody(e.target.value) }}
            />
            <p className="text-xs text-muted-foreground">
              Available: <code>{'{{.Login}}'}</code>, <code>{'{{.Product}}'}</code>,{' '}
              <code>{'{{.When}}'}</code>, <code>{'{{.ConsoleURL}}'}</code>
              {template.kind === 'invitation.issued' && (
                <>
                  , <code>{'{{.URL}}'}</code>
                </>
              )}
              . Anything else is refused when you save, rather than producing a
              message that silently fails to send.
            </p>
          </div>

          {error && (
            <Alert variant="destructive">
              <AlertTriangle className="size-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="flex gap-2">
            <Button size="sm" onClick={() => { save.mutate() }} disabled={save.isPending}>
              Save
            </Button>
            {template.overridden && (
              <Button size="sm" variant="outline" onClick={onReset}>
                <RotateCcw className="size-3" />
                Back to shipped wording
              </Button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function Field({
  label,
  value,
  onChange,
}: {
  label: string
  value: string
  onChange: (v: string) => void
}) {
  const id = label.toLowerCase().replace(/\s+/g, '-')
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} value={value} onChange={(e) => { onChange(e.target.value) }} />
    </div>
  )
}
