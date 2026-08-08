#!/usr/bin/env bash
#
# Puts locally built images where the cluster can see them.
#
# Docker Desktop's Kubernetes does not share Docker's image store — a pod
# referring to an image you just built fails with ErrImageNeverPull. Its node is
# a kind container running containerd, so the fix is the same one `kind load
# docker-image` uses: stream a `docker save` archive into the node's containerd
# under the k8s namespace.
#
# Cardinal itself is deliberately NOT loaded this way. It comes from Docker Hub
# as the published release, because pulling the actual artefact from a registry
# is what a real deployment does and rehearsing that is the point. To run local
# changes instead, build and load it and set the image on the deployment — the
# README says how.

set -euo pipefail

NODE="${K8S_NODE:-desktop-control-plane}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"

if ! docker exec "$NODE" true 2>/dev/null; then
	echo "cannot reach the cluster node container '$NODE'." >&2
	echo "Is Kubernetes enabled in Docker Desktop?" >&2
	exit 1
fi

build_and_load() {
	local image="$1" context="$2"
	echo "  building $image"
	docker build -q -t "$image" "$context" >/dev/null
	echo "  loading  $image"
	docker save "$image" | docker exec -i "$NODE" ctr -n k8s.io images import - >/dev/null
}

build_and_load cardinal-e2e-protected-app:latest "$ROOT/examples/protected-app"
build_and_load cardinal-e2e-oidc-client:latest "$ROOT/examples/oidc-client"

echo "  images in the cluster:"
docker exec "$NODE" crictl images 2>/dev/null \
	| grep -E 'protected-app|oidc-client' | sed 's/^/    /'
