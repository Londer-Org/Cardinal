import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'
import { createCredential } from '@/lib/webauthn'

export function useCredentials() {
  return useQuery({
    queryKey: queryKeys.credentials,
    queryFn: api.credentials.list,
  })
}

export function useRegisterCredential() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (name: string) => {
      const ceremony = await api.credentials.registerBegin()
      const attestation = await createCredential(ceremony.options)
      return api.credentials.registerFinish(
        ceremony.ceremonyId,
        attestation,
        name.trim() || 'Passkey',
      )
    },
    onSuccess: async () => {
      // Both: the credential list changes, and so does whether the account is
      // fully enrolled, which drives the banner on the account page.
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.credentials }),
        queryClient.invalidateQueries({ queryKey: queryKeys.me }),
      ])
    },
  })
}

export function useRevokeCredential() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: api.credentials.revoke,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.credentials }),
        queryClient.invalidateQueries({ queryKey: queryKeys.me }),
      ])
    },
  })
}
