#!/usr/bin/env bash
#
# Makes the cluster stack usable: a policy set, the two certificate authorities,
# a user, and a registered relying party.
#
# The equivalent of `make e2e-seed`, and it exists for the same reason — a
# migrated database with no policy and no accounts is one nobody can do anything
# with, and working that out from scratch each time is exactly the friction that
# stops people using the thing.
#
# Every command runs through `kubectl exec` against the distroless image, so
# there is no shell in the container: each is the binary invoked directly, and
# any conditional logic lives out here.

set -euo pipefail

CONTEXT="${K8S_CONTEXT:-docker-desktop}"
KUBECTL="${KUBECTL:-kubectl}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
CONFIG=/etc/cardinal/cardinal.toml

k() { "$KUBECTL" --context "$CONTEXT" "$@"; }
card() { k -n cardinal exec -i deploy/cardinal -- cardinal "$@"; }
psqlc() {
	k -n cardinal exec -i statefulset/postgres -- \
		psql -U cardinal -d cardinal -tAc "$1" 2>/dev/null | tr -d ' \r\n'
}
say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

say "A user"
# Errors are NOT swallowed. An earlier version of the compose equivalent used
# `|| true`, and a failed user creation surfaced much later as a confusing
# "session invalid" from a seeded session pointing at nothing.
#
# The output is captured before it is matched rather than piped into grep.
# Creating a user that exists exits non-zero, and under `set -o pipefail` that
# fails the whole pipeline even when grep found the reassuring message — so the
# obvious spelling reports a fatal error for the most ordinary case there is,
# running the script twice.
out="$(card user create k8s-user -display 'Kubernetes User' 2>&1 || true)"
if ! printf '%s' "$out" | grep -qE 'created|already exists'; then
	echo 'ERROR: could not create k8s-user' >&2
	printf '%s\n' "$out" >&2
	exit 1
fi
echo "  k8s-user"

say "Policy"
card policy publish /etc/cardinal/policies/cardinal.cedar \
	-description 'kubernetes stack' -activate | sed 's/^/  /'

say "Certificate authorities"
# -activate because nothing in this stack trusts an older key: the careful
# two-step ordering exists for a fleet that already has one, and there is no
# fleet here.
if ! card ssh ca list 2>/dev/null | grep -q signing; then
	card ssh ca init -activate -config "$CONFIG" >/dev/null
	echo "  SSH certificate authority created"
else
	echo "  SSH certificate authority already present"
fi
if ! card x509 ca list 2>/dev/null | grep -q signing; then
	card x509 ca init -activate -subject 'Cardinal Kubernetes CA' \
		-config "$CONFIG" >/dev/null 2>&1
	echo "  X.509 certificate authority created"
else
	echo "  X.509 certificate authority already present"
fi

say "Relying party"
# The client id is generated, so the relying party cannot be configured until
# Cardinal has issued one. Registering first and starting the client after is the
# only ordering that works.
WANT='https://client.cardinal.test/callback'
have="$(psqlc "SELECT coalesce(array_to_string(c.redirect_uris, ','), '')
                 FROM oidc_clients c JOIN entities e ON e.id = c.entity_id
                WHERE e.name = 'k8s-client'")"
if [ -z "$have" ]; then
	card app register k8s-client \
		-display 'Kubernetes relying party' \
		-redirect "$WANT" \
		-dev-mode \
		-scopes 'openid,profile,email,groups,offline_access' \
		-config "$CONFIG" >/dev/null
	echo "  registered k8s-client"
elif [ "$have" != "$WANT" ]; then
	echo "  redirect URI was $have — correcting it"
	k -n cardinal exec -i statefulset/postgres -- psql -U cardinal -d cardinal -q -c \
		"UPDATE oidc_clients SET redirect_uris = ARRAY['$WANT']
		  WHERE entity_id = (SELECT id FROM entities WHERE name = 'k8s-client')"
else
	echo "  k8s-client already registered"
fi

CLIENT_ID="$(psqlc "SELECT c.client_id FROM oidc_clients c
                      JOIN entities e ON e.id = c.entity_id
                     WHERE e.name = 'k8s-client'")"
[ -n "$CLIENT_ID" ] || { echo 'ERROR: no client id after registration' >&2; exit 1; }
echo "  client id $CLIENT_ID"

k -n example create configmap oidc-client-registration \
	--from-literal=client_id="$CLIENT_ID" \
	--dry-run=client -o yaml | k apply -f -

say "Restarting what reads this at startup"
# Only the relying party, which takes its client id from the environment.
#
# Cardinal is deliberately not restarted. It polls for an activated policy every
# ten seconds and swaps it in — the same mechanism the rollback button relies on
# — so restarting it here would buy nothing and briefly race Traefik's endpoint
# list, which is exactly how the host enrollment first failed with a 504.
k -n example rollout restart deployment/oidc-client
k -n example rollout status deployment/oidc-client --timeout=120s

say "Seeded"
