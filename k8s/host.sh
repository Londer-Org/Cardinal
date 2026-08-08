#!/usr/bin/env bash
#
# Joins a Linux machine to the Cardinal running in the cluster.
#
# The machine is a container, but nothing about how it reaches Cardinal is
# simulated: it resolves the same hostname a browser does, verifies the same
# certificate against the same local CA, enrolls over the network with a
# single-use token, and runs the agent that a .deb installed.
#
# This is the half the cluster cannot hold. cardinal-agent writes
# /etc/sudoers.d, serves a varlink socket nss-systemd must reach, and manages
# sshd's trust configuration — it belongs on a machine, not in the cluster it
# talks to.

set -euo pipefail

CONTEXT="${K8S_CONTEXT:-docker-desktop}"
KUBECTL="${KUBECTL:-kubectl}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
MACHINE="${CARDINAL_HOST_NAME:-k8s-host-01}"
WHO="${CARDINAL_HOST_USER:-k8s-user}"
NONROOT=k8s-nonroot
OUTSIDER=k8s-outsider
CONFIG=/etc/cardinal/cardinal.toml

k() { "$KUBECTL" --context "$CONTEXT" "$@"; }
card() { k -n cardinal exec -i deploy/cardinal -- cardinal "$@"; }
# Succeeds when the command succeeds, and additionally when it failed only
# because the thing already exists — which is the ordinary case on a second run.
#
# The exit code is what decides, not the text. An earlier version matched the
# output against a list of hopeful words and called anything else a failure, so
# `posix assign` reporting "uid = 100000" — a complete success — was treated as
# fatal. Reading the exit code is both simpler and correct.
tolerant() {
	local out rc=0
	out="$(card "$@" 2>&1)" || rc=$?
	[ "$rc" -eq 0 ] && return 0
	# Two spellings of "already assigned", deliberately.
	#
	# The cluster runs the published release, and 0.1.0 answers a second
	# assignment with the raw constraint violation — which is what this script
	# hitting it turned up. The friendly message arrives with the next release;
	# until then both have to be recognised, or a re-run is fatal.
	printf '%s' "$out" | grep -qiE \
		'already (exists|a member|assigned)|already has a POSIX|posix_identities_pkey' \
		&& return 0
	echo "ERROR: cardinal $*" >&2
	printf '%s\n' "$out" >&2
	exit 1
}
gid_of() {
	k -n cardinal exec -i statefulset/postgres -- psql -U cardinal -d cardinal -tAc \
		"SELECT id FROM entities WHERE type = 'group' AND name = '$1'" 2>/dev/null | tr -d ' \r\n'
}
say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# ── The agent package ──────────────────────────────────────────────────────
say "The cardinal-agent package"
DEB="$(ls "$ROOT"/dist/cardinal-agent_*_linux_amd64.deb 2>/dev/null | head -1 || true)"
if [ -z "$DEB" ]; then
	echo "  no .deb in dist/ — building one"
	(cd "$ROOT" && goreleaser release --snapshot --clean --skip=publish >/dev/null 2>&1)
	DEB="$(ls "$ROOT"/dist/cardinal-agent_*_linux_amd64.deb | head -1)"
fi
echo "  $(basename "$DEB")"

# ── Directory ──────────────────────────────────────────────────────────────
# Three groups, because the interesting questions need them apart: who may log
# in, which machines they may log into, and — separately — who may become root.
# A fixture where everyone who can log in can also sudo would pass any test.
say "Groups, and who is in them"
for g in k8s-linux-users k8s-linux-hosts k8s-linux-admins; do
	tolerant group create "$g"
done
tolerant posix assign group k8s-linux-users

# May log in, and may become root.
tolerant posix assign user "$WHO"
tolerant grant k8s-linux-users "$WHO"
tolerant grant k8s-linux-admins "$WHO"

# May log in, and may NOT become root. Without this account, "everybody gets
# root" and "the right people get root" are the same passing test.
tolerant user create "$NONROOT" -display 'Kubernetes User (no sudo)'
tolerant posix assign user "$NONROOT"
tolerant grant k8s-linux-users "$NONROOT"

# Has a uid and no grant at all. This is the one that proves the host is not
# simply being handed every numbered account in the directory — which is the
# whole difference from an LDAP-bound machine, where compromising the least
# important host in the fleet yields every name and uid in the company.
tolerant user create "$OUTSIDER" -display 'Kubernetes Outsider'
tolerant posix assign user "$OUTSIDER"

echo "  $WHO may log in and sudo; $NONROOT may log in only; $OUTSIDER neither"

say "The machine, as a directory entity"
tolerant host create "$MACHINE"
tolerant grant k8s-linux-hosts "$MACHINE"
echo "  $MACHINE is in k8s-linux-hosts"

# ── Policy ─────────────────────────────────────────────────────────────────
# The shipped policy names placeholder group UUIDs and says, in a comment,
# to replace them with real ones. That is what this does — rather than appending
# a parallel set of rules, which would leave two things claiming to govern host
# access and no way to tell which one answered.
say "Policy"
USERS="$(gid_of k8s-linux-users)"
HOSTS="$(gid_of k8s-linux-hosts)"
ADMINS="$(gid_of k8s-linux-admins)"
[ -n "$USERS" ] && [ -n "$HOSTS" ] && [ -n "$ADMINS" ] \
	|| { echo 'ERROR: groups were not created' >&2; exit 1; }

POLICY="$(mktemp)"
trap 'rm -f "$POLICY"' EXIT
sed \
	-e "s/00000000-0000-7000-8000-0000000e5be3/$USERS/g" \
	-e "s/00000000-0000-7000-8000-0000000e5be4/$HOSTS/g" \
	-e "s/00000000-0000-7000-8000-0000000e5be5/$ADMINS/g" \
	"$ROOT/policies/cardinal.cedar" > "$POLICY"

k -n cardinal create configmap cardinal-policies \
	--from-file=cardinal.cedar="$POLICY" --dry-run=client -o yaml | k apply -f - >/dev/null
# One restart, and only because kubelet projects a changed ConfigMap into the
# mount on its own schedule — `policy publish` reads the file from inside the
# pod, so it would otherwise publish the previous contents.
#
# There is deliberately no second restart after publishing. serve.go polls for
# an activated version every ten seconds (policyReloadInterval) and swaps it in,
# which is what makes the rollback button work. Restarting again raced Traefik's
# endpoint list and produced a 504 on the very next request.
k -n cardinal rollout restart deployment/cardinal >/dev/null
k -n cardinal rollout status deployment/cardinal --timeout=120s >/dev/null
card policy publish /etc/cardinal/policies/cardinal.cedar \
	-description "host access for $MACHINE" -activate | sed 's/^/  /'
echo "  waiting for the server to pick it up"
for _ in $(seq 1 20); do
	sleep 2
	loaded="$(k -n cardinal logs deploy/cardinal --tail=50 2>/dev/null \
		| grep -c 'policy set loaded' || true)"
	[ "${loaded:-0}" -gt 0 ] && break
done
echo "  activated"

# ── Build the machine ──────────────────────────────────────────────────────
say "Building the host image"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"; rm -f "$POLICY"' EXIT
cp "$HERE/host/Dockerfile" "$HERE/host/join.sh" "$BUILD/"
cp "$DEB" "$BUILD/cardinal-agent.deb"
cp "$ROOT/examples/traefik/tls/local-ca.pem" "$BUILD/local-ca.pem"
docker build -q -t cardinal-k8s-host "$BUILD" >/dev/null
echo "  cardinal-k8s-host"

# Through Traefik, not through the API server: the machine reaches Cardinal the
# same way a browser does, and a ready pod whose endpoint Traefik has not picked
# up yet answers one and not the other.
say "Waiting for the edge to route to a live server"
for _ in $(seq 1 60); do
	code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 https://id.cardinal.test/api/health || echo 000)"
	[ "$code" = "200" ] && break
	sleep 2
done
[ "$code" = "200" ] || { echo "ERROR: the edge never returned 200 (last $code)" >&2; exit 1; }
echo "  200"

say "A single-use enrollment token"
TOKEN="$(card host enroll "$MACHINE" -token -config "$CONFIG" 2>/dev/null | tr -d '\r\n ')"
[ -n "$TOKEN" ] || { echo 'ERROR: no enrollment token' >&2; exit 1; }
echo "  issued (${#TOKEN} characters, single use)"

# ── Run it ─────────────────────────────────────────────────────────────────
# --add-host points the cluster's hostname at the host gateway, which is where
# Docker Desktop forwards the LoadBalancer — so this machine resolves
# id.cardinal.test to the same place a browser on this laptop does.
say "Joining"
docker run --rm \
	--add-host "id.cardinal.test:host-gateway" \
	-e CARDINAL_SERVER="https://id.cardinal.test" \
	-e CARDINAL_TOKEN="$TOKEN" \
	-e CARDINAL_USER="$WHO" \
	-e CARDINAL_NONROOT="$NONROOT" \
	-e CARDINAL_OUTSIDER="$OUTSIDER" \
	-e CARDINAL_MACHINE="$MACHINE" \
	cardinal-k8s-host
