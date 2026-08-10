import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys, type SSFStreamRequest } from '@/lib/api'

/**
 * The receivers told when access changes, and whether delivery is working.
 *
 * One query rather than one per card: an operator asking "is anybody receiving
 * revocations, and is it working?" wants both halves, and splitting them would
 * mean a page that shows half the answer while the other half loads.
 */
export function useSSFStreams() {
  return useQuery({
    queryKey: queryKeys.ssfStreams,
    queryFn: () => api.ssfStreams.get(),
  })
}

export function useSaveSSFStream() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      application,
      stream,
    }: {
      application: string
      stream: SSFStreamRequest
    }) => api.ssfStreams.save(application, stream),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.ssfStreams })
    },
  })
}

export function useSetSSFStreamEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      application,
      enabled,
    }: {
      application: string
      enabled: boolean
    }) => api.ssfStreams.setEnabled(application, enabled),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.ssfStreams })
    },
  })
}

export function useDeleteSSFStream() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (application: string) => api.ssfStreams.remove(application),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.ssfStreams })
    },
  })
}
