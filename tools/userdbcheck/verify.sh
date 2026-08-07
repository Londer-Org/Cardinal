#!/bin/sh
# Asks getent what it thinks, and fails loudly if it disagrees.
#
# Every check here is one a Go test cannot make: whether nss-systemd finds the
# socket, accepts the record shape, and renders it the way the rest of the
# system expects.
set -eu

userdbcheck &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT

# Wait for the socket rather than sleeping a fixed time.
i=0
while [ ! -S /run/systemd/userdb/io.systemd.Cardinal ]; do
    i=$((i + 1))
    [ "$i" -gt 50 ] && { echo "FAIL: the provider never created its socket"; exit 1; }
    sleep 0.1
done

fail() { echo "FAIL: $1"; echo "  got: $2"; exit 1; }

# The GECOS field is the login, not empty. The provider deliberately omits
# realName — it is world-readable on every machine — and nss-systemd fills the
# gap with the user name rather than leaving it blank. Discovered here, because
# no Go test could have told us: it is glibc's rendering, not our record.
expected="cardinaltest:x:100000:100000:cardinaltest:/home/cardinaltest:/bin/bash"

echo "== getent passwd cardinaltest"
got=$(timeout 10 getent passwd cardinaltest || true)
echo "  $got"
[ "$got" = "$expected" ] || fail "passwd lookup by name" "$got"

echo "== getent passwd 100000"
got=$(timeout 10 getent passwd 100000 || true)
echo "  $got"
[ "$got" = "$expected" ] || fail "passwd lookup by uid" "$got"

echo "== getent group cardinalsre"
got=$(timeout 10 getent group cardinalsre || true)
echo "  $got"
case "$got" in
    cardinalsre:x:100001:*cardinaltest*) ;;
    *) fail "group lookup by name" "$got" ;;
esac

echo "== getent group 100001"
got=$(timeout 10 getent group 100001 || true)
echo "  $got"
case "$got" in
    cardinalsre:x:100001:*) ;;
    *) fail "group lookup by gid" "$got" ;;
esac

echo "== getent group cardinaltest (the synthesised user-private group)"
got=$(timeout 10 getent group cardinaltest || true)
echo "  $got"
case "$got" in
    cardinaltest:x:100000:*) ;;
    *) fail "the user-private group is not resolvable" "$got" ;;
esac

echo "== id cardinaltest"
got=$(timeout 10 id cardinaltest || true)
echo "  $got"
case "$got" in
    *"uid=100000(cardinaltest)"*"gid=100000"*) ;;
    *) fail "id" "$got" ;;
esac
# Supplementary group membership travels over GetMemberships, which is the one
# method that answers more than once — so this line is the only check that the
# streaming reply is correct as far as glibc is concerned.
case "$got" in
    *cardinalsre*) ;;
    *) fail "id does not show the supplementary group; GetMemberships is wrong" "$got" ;;
esac

echo "== a name nobody serves"
if timeout 10 getent passwd definitely-not-a-cardinal-user >/dev/null 2>&1; then
    fail "an unknown name resolved" "it should not exist"
fi
echo "  correctly absent"

echo "== getent passwd (enumeration)"
# Must not list Cardinal users: a host holds only its own people, so listing
# them would advertise exactly the set worth not advertising (ADR 0025).
if timeout 10 getent passwd | grep -q cardinaltest; then
    fail "enumeration disclosed a Cardinal user" "$(getent passwd | grep cardinaltest)"
fi
echo "  correctly absent from enumeration, and root is still listed:"
getent passwd root | sed 's/^/    /'

echo
echo "PASS: nss-systemd agrees with the provider"
