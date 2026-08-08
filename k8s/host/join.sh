#!/usr/bin/env bash
#
# Runs inside the host container. Enrolls against the Cardinal in the cluster,
# starts the agent, and then asks the machine's own tools what they believe.
#
# The questions are the ones no Go test can answer, and here they are asked of a
# host whose answers came over the network from a server in Kubernetes rather
# than from a provider running in the same process.

set -euo pipefail

SERVER="${CARDINAL_SERVER:?CARDINAL_SERVER is required}"
TOKEN="${CARDINAL_TOKEN:?CARDINAL_TOKEN is required}"
WHO="${CARDINAL_USER:?CARDINAL_USER is required}"
NONROOT="${CARDINAL_NONROOT:?CARDINAL_NONROOT is required}"
OUTSIDER="${CARDINAL_OUTSIDER:?CARDINAL_OUTSIDER is required}"
MACHINE="${CARDINAL_MACHINE:?CARDINAL_MACHINE is required}"

pass=0 fail=0
ok()  { printf '  \033[32m✓\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '  \033[31m✗\033[0m %s\n' "$*"; fail=$((fail + 1)); }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

say "Reaching the cluster"
if curl -fsS --max-time 10 "$SERVER/api/health" >/dev/null; then
	ok "$SERVER answers, and its certificate verifies against the local CA"
else
	bad "cannot reach $SERVER"
	exit 1
fi

say "Enrolling this machine"
# The agent generates its own keypair and sends only the public half, so Cardinal
# never holds a key that could impersonate this host.
cardinal-agent enroll -server "$SERVER" -token "$TOKEN"
ok "enrolled"

say "Starting the agent"
cardinal-agent run -server "$SERVER" \
	-interval 10s >/var/log/cardinal-agent.log 2>&1 &
AGENT_PID=$!

# Wait for the socket, rather than sleeping and hoping. The name is the agent's
# own service — nss-systemd scans the directory and speaks io.systemd.UserDatabase
# to whatever it finds there, so the file is io.systemd.Cardinal rather than
# anything named after NSS.
SOCK=/run/systemd/userdb/io.systemd.Cardinal
for _ in $(seq 1 60); do
	[ -S "$SOCK" ] && break
	sleep 0.5
done
if [ -S "$SOCK" ]; then
	ok "the varlink socket nss-systemd scans for exists ($SOCK)"
else
	bad "the agent never created its varlink socket"
	cat /var/log/cardinal-agent.log
	exit 1
fi

# The agent starts with no cached assignment and says so; nothing resolves until
# the first refresh completes. Waiting for the log line beats sleeping for a
# guess, and beats asking getent before there is anything to answer with.
for _ in $(seq 1 60); do
	grep -q 'assignment' /var/log/cardinal-agent.log && break
	sleep 0.5
done
sleep 2

say "What this machine now believes"
# The first question: does nss-systemd accept records that came from a server in
# Kubernetes? `getent` is asked, not the agent — the agent agreeing with itself
# would prove nothing.
if entry="$(getent passwd "$WHO")"; then
	ok "getent passwd $WHO -> $entry"
else
	bad "getent passwd $WHO found nothing"
	echo "--- agent log ---"; tail -20 /var/log/cardinal-agent.log
fi

if id "$WHO" >/dev/null 2>&1; then
	ok "id $WHO -> $(id "$WHO")"
else
	bad "id $WHO failed"
fi

# The second, and the one that matters: a sudoers rule naming a user is inert if
# sudo cannot resolve them. This spans both halves of the integration.
if sudo -l -U "$WHO" 2>/dev/null | grep -qiE 'may run|ALL'; then
	ok "sudo resolves $WHO and honours the rendered rules"
	sudo -l -U "$WHO" 2>/dev/null | sed 's/^/      /' | tail -4
else
	bad "sudo has nothing for $WHO"
	echo "      /etc/sudoers.d:"; ls -la /etc/sudoers.d/ | sed 's/^/      /'
fi

say "Sudo is decided separately from logging in"
# Two grants, two answers. A host that marked everyone who may log in as a sudoer
# would pass any check that only looked at the administrator.
if getent passwd "$NONROOT" >/dev/null 2>&1; then
	ok "$NONROOT resolves, so this machine knows they may log in"
else
	bad "$NONROOT does not resolve, but they are in the login group"
fi
if sudo -l -U "$NONROOT" 2>/dev/null | grep -qiE 'may run|NOPASSWD'; then
	bad "$NONROOT was granted sudo, and should not have been"
else
	ok "$NONROOT may log in and may NOT become root"
fi

say "A host learns only its own people"
# The headline claim of the design, and the whole difference from an LDAP-bound
# machine. The outsider has a uid and a home directory in the directory; what
# they do not have is permission to log into THIS machine, so this machine is
# never told they exist.
if getent passwd "$OUTSIDER" >/dev/null 2>&1; then
	bad "$OUTSIDER resolves here, and has no grant to this machine"
else
	ok "$OUTSIDER has a uid in the directory and does not resolve here"
fi

# The check that makes all of the above mean something. If getent answered for
# any name at all, it was not answering from the directory.
if getent passwd definitely-not-a-cardinal-user >/dev/null 2>&1; then
	bad "getent invented a record for a user that does not exist"
else
	ok "getent correctly finds nothing for an unknown name"
fi

say "Host certificate"
CERT=/etc/ssh/ssh_host_ed25519_key-cert.pub
if [ -f "$CERT" ]; then
	ok "the cluster's SSH authority signed this machine's host key"
	# Printed in full rather than grepped for a few headers. `Principals:` is a
	# label with the names on the following lines, so matching the label alone
	# printed an empty list and looked like a certificate valid for nothing.
	ssh-keygen -L -f "$CERT" 2>/dev/null | sed 's/^/      /'

	# And the principal has to be this machine, or the certificate proves the
	# authority signed something rather than that it signed *this host*.
	if ssh-keygen -L -f "$CERT" 2>/dev/null | grep -qw "$MACHINE"; then
		ok "and names $MACHINE as a principal"
	else
		bad "the certificate does not name $MACHINE"
	fi
else
	bad "no host certificate was installed"
fi

say "With the agent stopped"
# The check that proves where the answers were coming from.
#
# Everything above is consistent with the names having been in /etc/passwd all
# along — nothing so far distinguishes "the directory told this machine" from
# "somebody wrote it down locally". Stopping the agent settles it: the socket
# goes, and with it the identity.
kill "$AGENT_PID" 2>/dev/null || true
for _ in $(seq 1 20); do
	[ -S "$SOCK" ] || break
	sleep 0.5
done
if getent passwd "$WHO" >/dev/null 2>&1; then
	bad "$WHO still resolves with the agent stopped — these were local accounts"
else
	ok "$WHO stops resolving, so the directory was the source all along"
fi

# And the machine keeps its own root, which the agent is structurally incapable
# of removing. An identity system that can lock you out of your own hardware
# when it fails is a worse problem than the one it solves.
if getent passwd root >/dev/null 2>&1; then
	ok "local root survives, as it must"
else
	bad "local root is gone — the agent removed something it never should"
fi

say "Result"
printf '  %d passed, %d failed\n\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
