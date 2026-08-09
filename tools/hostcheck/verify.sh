#!/bin/sh
# Asks getent what it thinks, and fails loudly if it disagrees.
#
# Every check here is one a Go test cannot make: whether nss-systemd finds the
# socket, accepts the record shape, and renders it the way the rest of the
# system expects.
set -eu

# A user authority, generated here so the agent's own writer is what installs it
# and the certificate below is one a real client can present.
ssh-keygen -q -t ed25519 -N '' -C cardinal-user-ca -f /tmp/user-ca >/dev/null
CARDINAL_USER_CA="$(cat /tmp/user-ca.pub)"
export CARDINAL_USER_CA

hostcheck &
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

# ---------------------------------------------------------------------------
# sudo
#
# The integration that matters. A sudoers rule naming `cardinaltest` is inert if
# sudo cannot resolve the name, and it resolves it through the NSS path above —
# so this is the only check that proves the two halves work together.
# ---------------------------------------------------------------------------

echo
echo "== the drop-in the agent rendered"
sed 's/^/  /' /etc/sudoers.d/50-cardinal

echo "== sudo -l -U cardinaltest"
got=$(timeout 10 sudo -l -U cardinaltest 2>&1 || true)
echo "$got" | sed 's/^/  /'
case "$got" in
    *"NOPASSWD: ALL"*) ;;
    *) fail "sudo does not grant the rendered privilege" "$got" ;;
esac

echo "== sudo -l -U cardinalplain (resolvable, no grant)"
got=$(timeout 10 sudo -l -U cardinalplain 2>&1 || true)
echo "$got" | sed 's/^/  /'
case "$got" in
    *"NOPASSWD: ALL"*) fail "sudo granted root to somebody with no rule" "$got" ;;
esac
echo "  correctly ungranted"

echo "== actually running something as root"
# `sudo -u` needs a real uid to switch to and the whole point is that this one
# comes from Cardinal, not /etc/passwd.
got=$(timeout 10 sudo -n -u cardinaltest id -u 2>&1 || true)
echo "  sudo -u cardinaltest id -u → $got"
[ "$got" = "100000" ] || fail "sudo could not switch to a Cardinal-only user" "$got"

echo "== what a broken drop-in actually costs"
# Measured, not assumed. The received wisdom is that an unparseable file in
# sudoers.d bricks sudo for everybody; sudo 1.9 skips it and carries on. This
# records the real behaviour, so the justification for validating before
# installing rests on something that was checked.
printf 'this is not sudoers syntax\n' > /etc/sudoers.d/99-broken
chmod 0440 /etc/sudoers.d/99-broken

if ! timeout 10 sudo -l -U root >/dev/null 2>&1; then
    fail "sudo stopped working for root — the machine really is bricked" "worse than expected"
fi
echo "  root still works: sudo skips the broken file rather than refusing"

noise=$(timeout 10 sudo -l -U root 2>&1 >/dev/null || true)
case "$noise" in
    *"syntax error"*) ;;
    *) fail "sudo did not report the broken file at all" "$noise" ;;
esac
echo "  but every invocation prints: $(echo "$noise" | head -1)"

if timeout 10 visudo -c >/dev/null 2>&1; then
    fail "visudo -c accepted a configuration containing a broken file" "exit 0"
fi
echo "  and visudo -c now fails for the whole configuration"

rm -f /etc/sudoers.d/99-broken
timeout 10 sudo -l -U cardinaltest >/dev/null 2>&1 \
    || fail "sudo did not recover after the broken file was removed" "still failing"
echo "  recovers once removed"

# ---------------------------------------------------------------------------
# Host certificates
#
# The claim the feature rests on: a client that trusts the authority verifies
# the machine's name and is never asked to accept a fingerprint. No Go test can
# make it, because the only opinion that counts is a real ssh client's.
# ---------------------------------------------------------------------------

echo
echo "== the certificate Cardinal signed for this machine"
ssh-keygen -L -f /etc/ssh/ssh_host_ed25519_key-cert.pub | sed 's/^/  /'

got=$(ssh-keygen -L -f /etc/ssh/ssh_host_ed25519_key-cert.pub)
case "$got" in
    *"Type: ssh-ed25519-cert-v01@openssh.com host certificate"*) ;;
    *) fail "ssh-keygen does not read this as a host certificate" "$got" ;;
esac
case "$got" in
    *"Principals:"*"cardinal-verify"*) ;;
    *) fail "the principal is missing" "$got" ;;
esac
echo "  ssh-keygen reads it as a host certificate for cardinal-verify"

cat > /etc/ssh/sshd_config.d/50-cardinal.conf <<'CONF'
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
CONF
timeout 10 sshd -t || fail "sshd rejected the drop-in" "sshd -t failed"
echo "  sshd -t accepts the drop-in that presents it"

/usr/sbin/sshd -o "ListenAddress=127.0.0.1:2222" -o "PidFile=/tmp/sshd.pid"
i=0
while [ ! -f /tmp/sshd.pid ]; do
    i=$((i + 1))
    [ "$i" -gt 50 ] && { echo "FAIL: sshd did not start"; exit 1; }
    sleep 0.1
done

# One line, for the whole fleet. This is what replaces every fingerprint anybody
# would otherwise have been asked to accept.
mkdir -p /root/.ssh
printf '@cert-authority cardinal-verify %s' "$(cat /tmp/cardinal-ca.pub)" > /root/.ssh/known_hosts
chmod 600 /root/.ssh/known_hosts
echo "  known_hosts: $(cut -c1-60 /root/.ssh/known_hosts)…"

echo "== ssh with StrictHostKeyChecking=yes and no fingerprint on file"
# Host verification happens before user authentication, so "Permission denied"
# means the host was verified and only the login failed — which is exactly what
# is being tested. "Host key verification failed" would mean the opposite.
got=$(timeout 20 ssh -p 2222 -o StrictHostKeyChecking=yes -o BatchMode=yes \
        -o UserKnownHostsFile=/root/.ssh/known_hosts \
        -o HostKeyAlias=cardinal-verify \
        nobody@127.0.0.1 true 2>&1 || true)
echo "$got" | sed 's/^/  /'
case "$got" in
    *"Host key verification failed"*)
        fail "the client did not accept the certificate" "$got" ;;
    *"Permission denied"*) ;;
    *) fail "unexpected ssh outcome" "$got" ;;
esac
echo "  the host was verified by certificate; only the login was refused"

echo "== the same connection with the authority not trusted"
# The control. Without it the check above would pass just as happily against a
# client that verifies nothing.
printf '' > /root/.ssh/known_hosts
got=$(timeout 20 ssh -p 2222 -o StrictHostKeyChecking=yes -o BatchMode=yes \
        -o UserKnownHostsFile=/root/.ssh/known_hosts \
        -o HostKeyAlias=cardinal-verify \
        nobody@127.0.0.1 true 2>&1 || true)
case "$got" in
    *"Host key verification failed"*) ;;
    *) fail "ssh accepted an unknown host, so the check above proved nothing" "$got" ;;
esac
echo "  correctly refused — so the acceptance above was the certificate, not luck"

# ---------------------------------------------------------------------------
# User certificates, through the trust file the agent wrote
#
# The claim `cardinal ssh` rests on, and one no Go test can make: that sshd
# accepts a certificate signed by an authority the *agent* installed. The format
# check in writeUserCAKeys passes on files `sshd -t` also accepts — measured —
# so a login is the only thing that proves the file works.
# ---------------------------------------------------------------------------

echo "== the trust file the agent wrote"
[ -f /etc/ssh/cardinal_user_ca.pub ] || fail "the agent wrote no trust file" "absent"
grep -q "$(cut -d' ' -f2 /tmp/user-ca.pub)" /etc/ssh/cardinal_user_ca.pub \
    || fail "the trust file does not contain the authority" "$(cat /etc/ssh/cardinal_user_ca.pub)"
echo "  /etc/ssh/cardinal_user_ca.pub carries the authority"

cat > /etc/ssh/sshd_config.d/50-cardinal.conf <<'CONF'
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
TrustedUserCAKeys /etc/ssh/cardinal_user_ca.pub
CONF
timeout 10 sshd -t || fail "sshd rejected the drop-in naming the trust file" "sshd -t failed"
echo "  sshd -t accepts the drop-in naming it"

kill "$(cat /tmp/sshd.pid)" 2>/dev/null || true
rm -f /tmp/sshd.pid
/usr/sbin/sshd -o "ListenAddress=127.0.0.1:2222" -o "PidFile=/tmp/sshd.pid"
i=0
while [ ! -f /tmp/sshd.pid ]; do
    i=$((i + 1))
    [ "$i" -gt 50 ] && { echo "FAIL: sshd did not restart"; exit 1; }
    sleep 0.1
done

# A certificate for root, because root is the account this container has. What
# is under test is whether the signature and principal are honoured, which does
# not depend on which account it names.
ssh-keygen -q -t ed25519 -N '' -f /tmp/user-key >/dev/null
ssh-keygen -q -s /tmp/user-ca -I cardinal-verify -n root -V +5m /tmp/user-key.pub
echo "  signed a user certificate for root, valid five minutes"

printf '@cert-authority cardinal-verify %s' "$(cat /tmp/cardinal-ca.pub)" > /root/.ssh/known_hosts
chmod 600 /root/.ssh/known_hosts

echo "== ssh with the certificate and no password, no authorized_keys"
got=$(timeout 20 ssh -p 2222 -o StrictHostKeyChecking=yes -o BatchMode=yes \
        -o UserKnownHostsFile=/root/.ssh/known_hosts \
        -o HostKeyAlias=cardinal-verify \
        -o IdentitiesOnly=yes -i /tmp/user-key \
        root@127.0.0.1 'echo authenticated-by-certificate' 2>&1 || true)
echo "$got" | sed 's/^/  /'
case "$got" in
    *authenticated-by-certificate*) ;;
    *) fail "the certificate was refused, so the trust file does not work" "$got" ;;
esac
echo "  a certificate signed by the agent-installed authority was accepted"

echo "== the same certificate with the authority removed from the trust file"
# The control. Without it this would pass just as happily against an sshd that
# was letting root in for some other reason entirely.
printf '# emptied by the check\n' > /etc/ssh/cardinal_user_ca.pub
kill "$(cat /tmp/sshd.pid)" 2>/dev/null || true
rm -f /tmp/sshd.pid
/usr/sbin/sshd -o "ListenAddress=127.0.0.1:2222" -o "PidFile=/tmp/sshd.pid"
i=0
while [ ! -f /tmp/sshd.pid ]; do
    i=$((i + 1))
    [ "$i" -gt 50 ] && { echo "FAIL: sshd did not restart"; exit 1; }
    sleep 0.1
done
got=$(timeout 20 ssh -p 2222 -o StrictHostKeyChecking=yes -o BatchMode=yes \
        -o UserKnownHostsFile=/root/.ssh/known_hosts \
        -o HostKeyAlias=cardinal-verify \
        -o IdentitiesOnly=yes -i /tmp/user-key \
        root@127.0.0.1 'echo authenticated-by-certificate' 2>&1 || true)
case "$got" in
    *authenticated-by-certificate*)
        fail "the login succeeded with no authority trusted, so the check above proved nothing" "$got" ;;
    *) ;;
esac
echo "  correctly refused — so the acceptance above was the trust file, not luck"

# ---------------------------------------------------------------------------
# Shadow mode
#
# The comparison a migration turns on, run against real getent and real sudo.
# The interesting case is a uid that disagrees: an existing account with the same
# name and a different number. Here it is a plain /etc/passwd entry, because the
# comparison does not care where the machine's answer comes from — it asks
# getent, which is whatever NSS is configured with.
# ---------------------------------------------------------------------------

echo
echo "== a local account with the same name and a different uid"
useradd -u 4242 -m -s /bin/sh cardinalclash
getent passwd cardinalclash | sed 's/^/  /'

got=$(timeout 20 hostcheck -shadow 2>&1 || true)
echo "$got" | sed 's/^/  /'
case "$got" in
    *"uid"*"4242"*"blocking"*) ;;
    *) fail "shadow mode did not flag the uid mismatch as blocking" "$got" ;;
esac
echo "  correctly blocking"

echo "== the same comparison once the numbers agree"
userdel -r cardinalclash 2>/dev/null || true
# 100007 rather than a number the varlink provider is already serving: useradd
# consults NSS, so `useradd -u 100002` fails with "UID is not unique" because
# nss-systemd is answering for a user that exists only in Cardinal. Which is its
# own small proof the provider is in the chain.
# The group has to be created explicitly with a matching gid. Left to itself
# useradd picks the next free gid — 1000 — and the comparison then blocks on the
# gid instead, which is the check doing its job on a fixture that was wrong.
groupadd -g 100007 cardinalagree
useradd -u 100007 -g 100007 -m -d /home/cardinalagree -s /bin/bash cardinalagree
got=$(timeout 20 hostcheck -shadow -expect-name cardinalagree -expect-uid 100007 2>&1 || true)
echo "$got" | sed 's/^/  /'
case "$got" in
    *blocking*) fail "shadow mode blocked on an account that matches" "$got" ;;
esac
echo "  correctly clear — so the block above was the mismatch, not the default"

echo
echo "PASS: nss-systemd agrees with the provider, sudo honours the rendered file,"
echo "      a real ssh client verifies this machine by certificate, and shadow"
echo "      mode catches a uid that would silently reassign every file"
