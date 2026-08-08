#!/usr/bin/env bash
#
# Removes the stack. Same context guard as up.sh, and for the same reason.

set -euo pipefail

CONTEXT="${K8S_CONTEXT:-docker-desktop}"
KUBECTL="${KUBECTL:-kubectl}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

k() { "$KUBECTL" --context "$CONTEXT" "$@"; }

nodes="$(k get nodes -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)"
if [ "$nodes" != "desktop-control-plane" ]; then
	echo "refusing to delete anything: context '$CONTEXT' has nodes [$nodes]," >&2
	echo "which is not the single-node Docker Desktop cluster." >&2
	exit 1
fi

# Namespaces take the workloads, services, secrets and policies with them. The
# PersistentVolumeClaim goes too, which is the intent: this is a stack you throw
# away, and a surviving volume means the next `up` starts against a database
# somebody forgot was there.
k delete namespace cardinal example traefik --ignore-not-found --wait=false
echo "deleting namespaces (backgrounded; PVCs go with them)"
