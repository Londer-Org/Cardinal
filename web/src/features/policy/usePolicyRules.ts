import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys, type AddPolicyRuleRequest } from '@/lib/api'

/**
 * The live policy set, rule by rule.
 *
 * Invalidating the version list alongside it on every change, because adding a
 * rule publishes and activates a version — the two views are of the same thing
 * and one of them going stale is how somebody concludes the change did not take.
 */
export function usePolicyRules() {
  return useQuery({
    queryKey: queryKeys.policyRules,
    queryFn: api.policy.rules,
  })
}

function useRuleChange<TInput>(mutationFn: (input: TInput) => Promise<unknown>) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.policyRules }),
        queryClient.invalidateQueries({ queryKey: queryKeys.policyVersions }),
        queryClient.invalidateQueries({ queryKey: queryKeys.policy }),
      ])
    },
  })
}

export function useAddPolicyRule() {
  return useRuleChange((input: AddPolicyRuleRequest) => api.policy.addRule(input))
}

export function useRemovePolicyRule() {
  return useRuleChange((id: string) => api.policy.removeRule(id))
}
