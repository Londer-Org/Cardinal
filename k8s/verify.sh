#!/usr/bin/env bash
#
# Checks the cluster stack does what it claims.
#
# Every assertion here is one that can fail. That sounds obvious and is the
# thing this project keeps getting wrong: a check that cannot distinguish a
# working system from a broken one is worse than no check, because it reports
# success. Two in particular are written to be falsifiable —
#
#   - the network policy check connects from a pod that should be refused, and
#     `make k8s-verify-sabotage` deletes the policy to prove it then succeeds;
#   - the issuer check runs from inside a pod, not from the host, because the
#     failure it exists to catch is the issuer resolving to something different
#     in the cluster than in the browser.

set -euo pipefail

CONTEXT="${K8S_CONTEXT:-docker-desktop}"
KUBECTL="${KUBECTL:-kubectl}"
k() { "$KUBECTL" --context "$CONTEXT" "$@"; }

pass=0 fail=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; fail=$((fail + 1)); }
say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }

check_code() {
	local what="$1" url="$2" want="$3"
	local got
	got="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$url" || echo 000)"
	if [ "$got" = "$want" ]; then ok "$what ($got)"; else bad "$what — wanted $want, got $got"; fi
}

say "The identity platform, from the browser's side"
check_code "id.cardinal.test is up"           https://id.cardinal.test/api/health 200
check_code "the console is served"            https://id.cardinal.test/ 200

say "forwardAuth is what makes the difference"
# 401 rather than 200: Cardinal refuses an anonymous request and Traefik returns
# its answer instead of the application's.
check_code "app.cardinal.test refuses anonymous"  https://app.cardinal.test/ 401
# The same application, same pod, no middleware. It is up...
check_code "open.cardinal.test is the same app"   https://open.cardinal.test/healthz 200
# ...and it refuses to render, because nothing supplied identity headers. That
# contrast is the point: 401 is the proxy declining, 500 is the application
# noticing it was reached without one.
check_code "and without the proxy it has no identity" https://open.cardinal.test/ 500

say "The OIDC issuer is one identifier everywhere"
issuer="$(curl -s --max-time 10 https://id.cardinal.test/.well-known/openid-configuration \
	| python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])' 2>/dev/null || echo '')"
if [ "$issuer" = "https://id.cardinal.test" ]; then
	ok "discovery from the host reports $issuer"
else
	bad "discovery from the host reports '$issuer'"
fi

# The half that matters, and the half a host-side check cannot see. The relying
# party fetches discovery from inside the cluster, and the `iss` claim in every
# token is compared literally against what it found. If CoreDNS did not rewrite
# *.cardinal.test to Traefik, this resolves to nothing — or worse, to something
# that answers differently.
pod_issuer="$(k -n example run issuer-probe-$RANDOM --rm -i --restart=Never \
	--image=curlimages/curl:latest --command --quiet -- \
	curl -s --max-time 10 --insecure \
	https://id.cardinal.test/.well-known/openid-configuration 2>/dev/null \
	| python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])' 2>/dev/null || echo '')"
if [ "$pod_issuer" = "https://id.cardinal.test" ]; then
	ok "discovery from inside the cluster reports the same: $pod_issuer"
else
	bad "discovery from inside the cluster reports '$pod_issuer' — CoreDNS rewrite?"
fi

say "The estates are separate"
# The rule that matters. An identity platform's datastore holds every credential
# hash, every session and the audit journal. In examples/compose.yml every
# container shares one network and this connection succeeds; here it must not.
#
# A refusal shows up as a timeout rather than a reset, because a NetworkPolicy
# drops rather than rejects — so the timeout is short and its expiry is the pass.
if k -n example run netpol-probe-$RANDOM --rm -i --restart=Never \
	--image=postgres:19beta2 --command --quiet -- \
	timeout 8 psql "postgres://cardinal:cardinal@postgres.cardinal.svc.cluster.local:5432/cardinal" \
	-tAc 'select 1' >/dev/null 2>&1; then
	bad "an example-namespace pod REACHED Cardinal's database"
else
	ok "an example-namespace pod cannot reach Cardinal's database"
fi

# Cardinal answers the edge and only the edge.
if k -n example run direct-probe-$RANDOM --rm -i --restart=Never \
	--image=curlimages/curl:latest --command --quiet -- \
	curl -s --max-time 8 http://cardinal.cardinal.svc.cluster.local:8080/api/health \
	>/dev/null 2>&1; then
	bad "an example-namespace pod REACHED Cardinal directly, bypassing the edge"
else
	ok "an example-namespace pod cannot reach Cardinal directly"
fi

say "Result"
printf '  %d passed, %d failed\n\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
