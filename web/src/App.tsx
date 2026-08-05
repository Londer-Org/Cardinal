import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, type Credential, type Me } from './api'
import {
  createCredential,
  getCredential,
  isSupported,
  WebAuthnError,
} from './webauthn'

export function App() {
  const { data: me, isPending, isError } = useQuery({
    queryKey: ['me'],
    queryFn: api.me,
    retry: false,
  })

  if (isPending) {
    return <Centered><p className="text-slate-500">Loading…</p></Centered>
  }
  if (isError) {
    return <Login />
  }
  return <Account me={me} />
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-dvh grid place-items-center bg-slate-50 p-6 dark:bg-slate-950">
      <div className="w-full max-w-md">{children}</div>
    </div>
  )
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      {children}
    </div>
  )
}

function Login() {
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)

  const login = useMutation({
    mutationFn: async () => {
      // No username field, deliberately. A discoverable ceremony lets the user
      // pick an account from their authenticator, which removes username
      // enumeration as an attack surface entirely.
      const ceremony = await api.loginBegin()
      const assertion = await getCredential(ceremony.options)
      await api.loginFinish(ceremony.ceremonyId, assertion)
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['me'] })
    },
    onError: (err: unknown) => {
      setError(messageFor(err))
    },
  })

  if (!isSupported()) {
    return (
      <Centered>
        <Card>
          <h1 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
            Cardinal
          </h1>
          <p className="mt-3 text-sm text-slate-600 dark:text-slate-400">
            This browser does not support passkeys. Cardinal has no passwords, so
            a browser with WebAuthn support is required.
          </p>
        </Card>
      </Centered>
    )
  }

  return (
    <Centered>
      <Card>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
          Cardinal
        </h1>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
          Sign in with your passkey.
        </p>

        <button
          type="button"
          onClick={() => { setError(null); login.mutate() }}
          disabled={login.isPending}
          className="mt-6 w-full rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-medium text-white
                     hover:bg-slate-700 disabled:opacity-50 dark:bg-slate-100 dark:text-slate-900
                     dark:hover:bg-slate-300"
        >
          {login.isPending ? 'Waiting for your device…' : 'Sign in'}
        </button>

        {error !== null && <ErrorNote>{error}</ErrorNote>}
      </Card>
    </Centered>
  )
}

function Account({ me }: { me: Me }) {
  const queryClient = useQueryClient()
  const { data: credentials } = useQuery({
    queryKey: ['credentials'],
    queryFn: api.credentials,
  })

  const logout = useMutation({
    mutationFn: api.logout,
    onSuccess: () => { queryClient.clear() },
  })

  return (
    <div className="min-h-dvh bg-slate-50 p-6 dark:bg-slate-950">
      <div className="mx-auto max-w-2xl space-y-4">
        <header className="flex items-baseline justify-between">
          <div>
            <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
              {me.displayName || me.login}
            </h1>
            <p className="text-sm text-slate-500">{me.login}</p>
          </div>
          <button
            type="button"
            onClick={() => { logout.mutate() }}
            className="text-sm text-slate-500 underline hover:text-slate-900 dark:hover:text-slate-200"
          >
            Sign out
          </button>
        </header>

        {me.emergency && (
          <Banner tone="danger">
            <strong>Emergency access in progress.</strong> This session was opened
            with the break-glass key and is being audited. Restore normal access
            and sign out as soon as you can.
          </Banner>
        )}

        {!me.fullyEnrolled && (
          <Banner tone="warning">
            <strong>Register a second passkey.</strong> With only one, losing that
            device means losing the account. A hardware key kept somewhere else is
            the usual second.
          </Banner>
        )}

        {me.recoveryCodesRemaining === 0 && (
          <Banner tone="warning">
            <strong>No recovery codes.</strong> Generate a set and store them
            offline.
          </Banner>
        )}

        <Credentials credentials={credentials ?? []} />
        <RecoveryCodes remaining={me.recoveryCodesRemaining} />
      </div>
    </div>
  )
}

function Credentials({ credentials }: { credentials: Credential[] }) {
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const [name, setName] = useState('')

  const register = useMutation({
    mutationFn: async () => {
      const ceremony = await api.registerBegin()
      const attestation = await createCredential(ceremony.options)
      await api.registerFinish(
        ceremony.ceremonyId,
        attestation,
        name.trim() || 'Passkey',
      )
    },
    onSuccess: () => {
      setName('')
      void queryClient.invalidateQueries({ queryKey: ['credentials'] })
      void queryClient.invalidateQueries({ queryKey: ['me'] })
    },
    onError: (err: unknown) => { setError(messageFor(err)) },
  })

  const revoke = useMutation({
    mutationFn: api.revokeCredential,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['credentials'] })
      void queryClient.invalidateQueries({ queryKey: ['me'] })
    },
    onError: (err: unknown) => { setError(messageFor(err)) },
  })

  return (
    <Card>
      <h2 className="font-semibold text-slate-900 dark:text-slate-100">Passkeys</h2>

      <ul className="mt-4 divide-y divide-slate-100 dark:divide-slate-800">
        {credentials.map((c) => (
          <li key={c.id} className="flex items-center justify-between py-3">
            <div>
              <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                {c.name}
              </p>
              <p className="text-xs text-slate-500">
                {c.deviceBound ? 'Device-bound' : 'Synced'}
                {c.lastUsedAt !== null && ` · last used ${formatDate(c.lastUsedAt)}`}
              </p>
            </div>
            <button
              type="button"
              onClick={() => { setError(null); revoke.mutate(c.id) }}
              disabled={credentials.length <= 1}
              title={credentials.length <= 1
                ? 'You cannot remove your only passkey'
                : undefined}
              className="text-sm text-slate-500 underline hover:text-red-600 disabled:no-underline
                         disabled:opacity-40"
            >
              Remove
            </button>
          </li>
        ))}
        {credentials.length === 0 && (
          <li className="py-3 text-sm text-slate-500">No passkeys registered.</li>
        )}
      </ul>

      <div className="mt-4 flex gap-2">
        <input
          value={name}
          onChange={(e) => { setName(e.target.value) }}
          placeholder="Name this device"
          maxLength={64}
          className="flex-1 rounded-lg border border-slate-200 px-3 py-2 text-sm
                     dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
        />
        <button
          type="button"
          onClick={() => { setError(null); register.mutate() }}
          disabled={register.isPending}
          className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white
                     hover:bg-slate-700 disabled:opacity-50 dark:bg-slate-100 dark:text-slate-900"
        >
          {register.isPending ? 'Waiting…' : 'Add passkey'}
        </button>
      </div>

      {error !== null && <ErrorNote>{error}</ErrorNote>}
    </Card>
  )
}

function RecoveryCodes({ remaining }: { remaining: number }) {
  const queryClient = useQueryClient()
  const [codes, setCodes] = useState<string[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  const generate = useMutation({
    mutationFn: api.generateRecoveryCodes,
    onSuccess: (data) => {
      setCodes(data.codes)
      void queryClient.invalidateQueries({ queryKey: ['me'] })
    },
    onError: (err: unknown) => { setError(messageFor(err)) },
  })

  return (
    <Card>
      <h2 className="font-semibold text-slate-900 dark:text-slate-100">
        Recovery codes
      </h2>
      <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
        {remaining} unused. Single-use, and shown only once.
      </p>

      {codes !== null && (
        <div className="mt-4 rounded-lg border border-amber-300 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950/40">
          <p className="text-sm font-medium text-amber-900 dark:text-amber-200">
            Store these offline now. They cannot be shown again, and any earlier
            set has been invalidated.
          </p>
          <ul className="mt-3 grid grid-cols-2 gap-1 font-mono text-sm text-amber-950 dark:text-amber-100">
            {codes.map((code) => <li key={code}>{code}</li>)}
          </ul>
        </div>
      )}

      <button
        type="button"
        onClick={() => { setError(null); generate.mutate() }}
        disabled={generate.isPending}
        className="mt-4 rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium
                   text-slate-900 hover:bg-slate-50 disabled:opacity-50
                   dark:border-slate-700 dark:text-slate-100 dark:hover:bg-slate-800"
      >
        {remaining > 0 ? 'Regenerate codes' : 'Generate codes'}
      </button>

      {error !== null && <ErrorNote>{error}</ErrorNote>}
    </Card>
  )
}

function Banner({ tone, children }: { tone: 'warning' | 'danger'; children: React.ReactNode }) {
  const styles = tone === 'danger'
    ? 'border-red-300 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200'
    : 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200'
  return (
    <div className={`rounded-lg border p-4 text-sm ${styles}`} role="alert">
      {children}
    </div>
  )
}

function ErrorNote({ children }: { children: React.ReactNode }) {
  return (
    <p className="mt-3 text-sm text-red-600 dark:text-red-400" role="alert">
      {children}
    </p>
  )
}

/** Surfaces a message a person can act on, rather than a stringified object. */
function messageFor(err: unknown): string {
  if (err instanceof WebAuthnError || err instanceof ApiError) {
    return err.message
  }
  if (err instanceof Error) {
    return err.message
  }
  return 'Something went wrong.'
}

function formatDate(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? 'unknown' : date.toLocaleDateString()
}
