#!/usr/bin/env bash
#
# Brings up the Kubernetes stack on Docker Desktop.
#
# Everything here pins --context explicitly and refuses to run against anything
# else. That is not paranoia: kubeconfig on this machine also holds production
# OpenShift clusters, and `kubectl apply -f k8s/` with the wrong context selected
# is a single keystroke away from being a very bad afternoon.

set -euo pipefail

CONTEXT="${K8S_CONTEXT:-docker-desktop}"
KUBECTL="${KUBECTL:-kubectl}"
TRAEFIK_VERSION="${TRAEFIK_VERSION:-v3.6}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"

k() { "$KUBECTL" --context "$CONTEXT" "$@"; }

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# ── Guard ──────────────────────────────────────────────────────────────────
# The one check worth having. A cluster called docker-desktop whose only node is
# a kind control plane is this machine's throwaway; anything else is somebody's
# real estate.
say "Checking the target cluster"
if ! "$KUBECTL" config get-contexts -o name | grep -qx "$CONTEXT"; then
	echo "context '$CONTEXT' does not exist." >&2
	echo "Enable Kubernetes in Docker Desktop, or set K8S_CONTEXT." >&2
	exit 1
fi
nodes="$(k get nodes -o jsonpath='{.items[*].metadata.name}')"
if [ "$nodes" != "desktop-control-plane" ]; then
	echo "refusing to continue: context '$CONTEXT' has nodes [$nodes]," >&2
	echo "which is not the single-node Docker Desktop cluster this script expects." >&2
	exit 1
fi
echo "  $CONTEXT — $nodes"

# ── Certificates ───────────────────────────────────────────────────────────
# The same mkcert material the compose stack uses, for the same reason: WebAuthn
# needs a secure context, and a self-signed certificate the browser does not
# trust is not one.
say "TLS material"
if [ ! -f "$ROOT/examples/traefik/tls/cardinal.test.crt" ]; then
	mkdir -p "$ROOT/examples/traefik/tls"
	(cd "$ROOT/examples/traefik/tls" && mkcert \
		-cert-file cardinal.test.crt -key-file cardinal.test.key \
		id.cardinal.test app.cardinal.test client.cardinal.test \
		open.cardinal.test cardinal.test) 2>/dev/null
	echo "  issued a certificate for *.cardinal.test"
fi
cp -f "$(mkcert -CAROOT)/rootCA.pem" "$ROOT/examples/traefik/tls/local-ca.pem"

# ── Namespaces ─────────────────────────────────────────────────────────────
say "Namespaces"
k apply -f "$HERE/00-namespaces.yaml"

# Secrets are created imperatively rather than committed, because one of them is
# a private key. Same reasoning as the compose stack: the certificate is
# worthless, and committing private keys is still a habit not worth having.
k -n traefik create secret tls cardinal-test-tls \
	--cert="$ROOT/examples/traefik/tls/cardinal.test.crt" \
	--key="$ROOT/examples/traefik/tls/cardinal.test.key" \
	--dry-run=client -o yaml | k apply -f -
k -n example create secret generic local-ca \
	--from-file=local-ca.pem="$ROOT/examples/traefik/tls/local-ca.pem" \
	--dry-run=client -o yaml | k apply -f -

# ── Traefik ────────────────────────────────────────────────────────────────
say "Traefik $TRAEFIK_VERSION"
k apply --server-side -f \
	"https://raw.githubusercontent.com/traefik/traefik/${TRAEFIK_VERSION}/docs/content/reference/dynamic-configuration/kubernetes-crd-definition-v1.yml"
k apply -f "$HERE/edge/traefik.yaml"
k apply -f "$HERE/edge/middlewares.yaml"

# ── DNS ────────────────────────────────────────────────────────────────────
# The piece with no compose equivalent, and the one that makes OIDC work.
#
# compose gave Traefik network aliases so a container resolving id.cardinal.test
# reached the proxy. Here CoreDNS rewrites the whole *.cardinal.test zone to the
# Traefik service, so the relying party pod fetches discovery from exactly the
# URL the browser uses. An OIDC issuer must be one identifier everywhere: the
# value in the token has to match what the client discovered, and papering over a
# difference with a separate internal URL is how "issuer mismatch" reaches
# production.
say "CoreDNS rewrite for *.cardinal.test"
"$HERE/dns/patch-coredns.sh" "$CONTEXT" "$KUBECTL"

# ── Images ─────────────────────────────────────────────────────────────────
say "Images"
"$HERE/load-images.sh"

# ── Workloads ──────────────────────────────────────────────────────────────
say "Cardinal"
# The Cedar policy set, from the same file the compose stack publishes. A
# ConfigMap rather than `kubectl cp`, which shells out to tar inside the
# container and so cannot work against a distroless image.
k -n cardinal create configmap cardinal-policies \
	--from-file=cardinal.cedar="$ROOT/policies/cardinal.cedar" \
	--dry-run=client -o yaml | k apply -f -
k apply -f "$HERE/cardinal/postgres.yaml"
k -n cardinal rollout status statefulset/postgres --timeout=180s
k apply -f "$HERE/cardinal/cardinal.yaml"

say "Example estate"
k apply -f "$HERE/example/apps.yaml"

say "Network policy"
k apply -f "$HERE/90-networkpolicy.yaml"

say "Waiting for everything to be ready"
k -n cardinal wait --for=condition=complete job/cardinal-migrate --timeout=180s
k -n cardinal rollout status deployment/cardinal --timeout=180s
k -n traefik rollout status deployment/traefik --timeout=180s
k -n example rollout status deployment/protected-app --timeout=180s
k -n example rollout status deployment/oidc-client --timeout=180s

say "Seeding"
"$HERE/seed.sh"

say "Up"
cat <<'EOF'
  https://id.cardinal.test      the identity platform
  https://app.cardinal.test     an application behind forwardAuth
  https://client.cardinal.test  an OpenID Connect relying party
  https://open.cardinal.test    the same application with no auth, for contrast

These need /etc/hosts entries. `make hosts-line` prints them.
EOF
