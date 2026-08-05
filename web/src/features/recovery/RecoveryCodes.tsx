import { AlertTriangleIcon, RefreshCwIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useGenerateRecoveryCodes } from './useRecoveryCodes'

export function RecoveryCodes({ remaining }: { remaining: number }) {
  const generate = useGenerateRecoveryCodes()
  const codes = generate.data?.codes

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recovery codes</CardTitle>
        <CardDescription>
          {remaining} unused. Each works once, and they are shown only when
          generated.
        </CardDescription>
      </CardHeader>

      <CardContent>
        {codes !== undefined && (
          <Alert className="mb-4 border-warning/50 text-warning-foreground [&>svg]:text-warning">
            <AlertTriangleIcon />
            <AlertTitle>Store these offline now</AlertTitle>
            <AlertDescription className="block">
              <p className="mb-3">
                They cannot be shown again, and any set issued earlier has been
                invalidated.
              </p>
              <ul className="grid grid-cols-2 gap-x-6 gap-y-1 font-mono text-sm">
                {codes.map((code) => (
                  <li key={code}>{code}</li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        )}

        <Button
          variant="outline"
          onClick={() => { generate.mutate() }}
          disabled={generate.isPending}
        >
          <RefreshCwIcon />
          {remaining > 0 ? 'Regenerate codes' : 'Generate codes'}
        </Button>

        <ErrorMessage error={generate.error} />
      </CardContent>
    </Card>
  )
}
