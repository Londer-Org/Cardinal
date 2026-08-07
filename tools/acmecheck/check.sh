#!/usr/bin/env bash
# Drive Cardinal's ACME server with a real client.
#
# lego, not our own code. Every other assurance here is Cardinal agreeing with
# Cardinal — this is the only check that says an implementation nobody on this
# project wrote will talk to it, which is the entire claim of ADR 0023: "a
# consumer points at Cardinal instead of Let's Encrypt and learns nothing new".
#
# Needs `make e2e-up` and lego on PATH:
#   go install github.com/go-acme/lego/v4/cmd/lego@latest
set -euo pipefail

cd "$(dirname "$0")/../.."

COMPOSE="docker compose -f examples/compose.yml"
CARDINAL="$COMPOSE exec -T cardinal cardinal"
CONF="-config /etc/cardinal/cardinal.toml"
DIRECTORY="${DIRECTORY:-https://id.localhost:8543/acme/directory}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

command -v lego >/dev/null || {
    echo "lego is not on PATH: go install github.com/go-acme/lego/v4/cmd/lego@latest" >&2
    exit 2
}
export LEGO_CA_CERTIFICATES="$PWD/examples/traefik/tls/e2e.crt"

fail() { echo "FAIL: $1"; [ $# -gt 1 ] && echo "  got: $2"; exit 1; }

# Unique per run: an EAB credential is single use, and a host that already has
# an account would exercise a different path than the one being checked.
HOST="acmecheck-$$.prod"
ALIAS="acmecheck-alias-$$.example"
OTHER="acmecheck-other-$$.prod"

echo "== seeding"
$CARDINAL host create "$HOST" >/dev/null
$CARDINAL host create "$OTHER" >/dev/null
$CARDINAL host alias add "$HOST" "$ALIAS" >/dev/null
echo "  $HOST, with the alias $ALIAS, and $OTHER for it to be refused"

credentials() {
    $CARDINAL host acme-credentials "$1" $CONF 2>/dev/null
}

run_lego() {
    local dir="$1"; shift
    local creds kid hmac
    creds=$(credentials "$HOST")
    kid=$(echo "$creds" | awk '/^kid/{print $2}')
    hmac=$(echo "$creds" | awk '/^hmac/{print $2}')
    [ -n "$kid" ] || fail "no EAB credential was issued"

    mkdir -p "$WORK/$dir"
    lego --server "$DIRECTORY" --email "$dir@example.com" \
         --eab --kid "$kid" --hmac "$hmac" \
         --path "$WORK/$dir" --accept-tos \
         --http --http.port ":$((5100 + RANDOM % 400))" \
         "$@" 2>&1
}

echo "== a real client obtains a certificate"
out=$(run_lego first --domains "$HOST" run) || fail "lego could not obtain a certificate" "$out"
echo "$out" | grep -E "authorization already valid|Server responded" | sed 's/^/  /'

case "$out" in
    *"authorization already valid; skipping challenge"*) ;;
    *) fail "the client was made to answer a challenge" "$out" ;;
esac
echo "  no challenge was needed — control of the name came from the directory"

CERT="$WORK/first/certificates/$HOST.crt"
[ -f "$CERT" ] || fail "no certificate was written"

echo "== what it got"
openssl x509 -in "$CERT" -noout -subject -issuer -ext subjectAltName 2>/dev/null | sed 's/^/  /'

$CARDINAL x509 ca trust > "$WORK/ca.pem" 2>/dev/null
openssl verify -CAfile "$WORK/ca.pem" "$CERT" >/dev/null 2>&1 \
    || fail "the certificate does not chain to the authority"
echo "  verifies against the authority"

echo "== a name belonging to another machine is refused"
out=$(run_lego second --domains "$OTHER" run) && fail "another machine's name was issued" "$out"
case "$out" in
    *rejectedIdentifier*) ;;
    *) fail "refused for the wrong reason" "$out" ;;
esac
echo "  rejectedIdentifier, naming the fix:"
echo "$out" | grep -o "may not hold a certificate for [^;]*" | head -1 | sed 's/^/    /'

echo "== its own alias is issued"
out=$(run_lego third --domains "$HOST" --domains "$ALIAS" run) \
    || fail "an entitled alias was refused" "$out"
names=$(openssl x509 -in "$WORK/third/certificates/$HOST.crt" -noout -ext subjectAltName 2>/dev/null)
case "$names" in
    *"$ALIAS"*) ;;
    *) fail "the alias is missing from the certificate" "$names" ;;
esac
echo "  both names on one certificate"

echo "== a spent credential cannot be reused"
creds=$(credentials "$HOST")
kid=$(echo "$creds" | awk '/^kid/{print $2}')
hmac=$(echo "$creds" | awk '/^hmac/{print $2}')
mkdir -p "$WORK/spend-a" "$WORK/spend-b"
lego --server "$DIRECTORY" --email "a@example.com" --eab --kid "$kid" --hmac "$hmac" \
     --path "$WORK/spend-a" --accept-tos --domains "$HOST" \
     --http --http.port :5601 run >/dev/null 2>&1 \
     || fail "the first use of a fresh credential failed"
if lego --server "$DIRECTORY" --email "b@example.com" --eab --kid "$kid" --hmac "$hmac" \
        --path "$WORK/spend-b" --accept-tos --domains "$HOST" \
        --http --http.port :5602 run >/dev/null 2>&1; then
    fail "a spent EAB credential was accepted a second time"
fi
echo "  single use, as issued"

echo
echo "PASS: a client nobody here wrote obtains certificates from Cardinal,"
echo "      is refused names the directory has not granted, and needs no challenge"
