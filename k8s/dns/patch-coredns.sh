#!/usr/bin/env bash
#
# Teaches the cluster's DNS that *.cardinal.test is Traefik.
#
# This is the Kubernetes equivalent of the network aliases in
# examples/compose.yml, and it exists for the same non-negotiable reason: the
# OIDC relying party fetches discovery from the issuer URL, and that URL has to
# be the one the browser used, because the `iss` claim in every token is compared
# literally against what the client discovered.
#
# Written as a rewrite rather than a hosts entry so it does not need Traefik's
# ClusterIP, which is not known until the Service exists and changes if it is
# recreated.

set -euo pipefail

CONTEXT="${1:-docker-desktop}"
KUBECTL="${2:-kubectl}"
k() { "$KUBECTL" --context "$CONTEXT" "$@"; }

MARKER='rewrite name regex (.*)\.cardinal\.test traefik.traefik.svc.cluster.local'

current="$(k -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')"

if printf '%s' "$current" | grep -qF 'cardinal.test'; then
	echo "  already present"
	exit 0
fi

# Inserted immediately after the opening of the server block, because CoreDNS
# applies rewrite before the kubernetes plugin resolves — the order matters, and
# appending at the end would rewrite nothing.
patched="$(printf '%s' "$current" | awk -v rule="    $MARKER" '
	{ print }
	/^\.:53 \{/ && !done { print rule; done = 1 }
')"

k -n kube-system create configmap coredns \
	--from-literal=Corefile="$patched" \
	--dry-run=client -o yaml | k -n kube-system apply -f -

# CoreDNS reloads on its own within a minute or two, but nothing downstream
# should have to wait that long to find out whether this worked.
k -n kube-system rollout restart deployment/coredns
k -n kube-system rollout status deployment/coredns --timeout=90s

echo "  *.cardinal.test -> traefik.traefik.svc.cluster.local"
