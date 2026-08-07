#!/bin/sh
# What the package installs, and what installing it does to a machine.
#
# The first draft of this asserted that installing changed nothing about how the
# machine resolves usernames. That was false, and the check caught it: Cardinal's
# package ships no maintainer scripts, but it depends on libnss-systemd, whose
# postinst adds `systemd` to nsswitch.conf. So the properties worth asserting are
# the true ones — Cardinal writes nothing outside its own paths, and the NSS
# change its dependency makes is additive rather than a cutover.
set -eu

fail() { echo "FAIL: $1"; [ $# -gt 1 ] && echo "  got: $2"; exit 1; }

# A machine already using another directory, which is the migration case and the
# one where getting the ordering wrong would silently override it.
sed -i 's/^passwd:.*/passwd:         files sss/; s/^group:.*/group:          files sss/' \
    /etc/nsswitch.conf
cp /etc/sudoers /etc/sudoers.pristine

echo "== installing the package"
apt-get update >/dev/null
apt-get install -y --no-install-recommends /tmp/cardinal-agent.deb 2>&1 | tail -3

echo "== what it put on disk"
for f in /usr/bin/cardinal-agent \
         /usr/lib/systemd/system/cardinal-agent.service \
         /etc/cardinal/agent.toml; do
    [ -e "$f" ] || fail "missing $f"
    echo "  $f"
done
[ -d /var/lib/cardinal ] || fail "missing /var/lib/cardinal"
echo "  /var/lib/cardinal"

echo "== Cardinal's own package ships no maintainer scripts"
# The property that is actually Cardinal's to keep. Whatever the machine ends up
# looking like, none of it was done by code in this package.
scripts=$(dpkg-query --control-list cardinal-agent 2>/dev/null || true)
case "$scripts" in
    *preinst*|*postinst*|*prerm*|*postrm*)
        fail "the package ships maintainer scripts" "$scripts" ;;
esac
echo "  none"

echo "== the dependency that makes it work at all"
dpkg -l libnss-systemd >/dev/null 2>&1 \
    || fail "libnss-systemd was not pulled in; nothing would ever consult the agent"
echo "  libnss-systemd installed as a dependency"

echo "== and what that dependency did to nsswitch.conf"
grep -E '^(passwd|group):' /etc/nsswitch.conf | sed 's/^/  /'
# It appends rather than inserts, so a directory already on the line keeps
# winning for any name both know. That is the ordering a migration needs:
# installing the package does not cut anybody over, and shadow mode stays
# meaningful because the agent is not yet the thing being asked (ADR 0020).
for db in passwd group; do
    line=$(grep "^$db:" /etc/nsswitch.conf)
    case "$line" in
        *sss*systemd*) ;;
        *systemd*sss*) fail "systemd was placed before the existing directory, \
which would cut this machine over on install" "$line" ;;
        *) fail "$db line is not what was expected" "$line" ;;
    esac
done
echo "  systemd appended after the existing directory — additive, not a cutover"

echo "== /etc/sudoers was not touched"
diff -q /etc/sudoers.pristine /etc/sudoers >/dev/null \
    || fail "installing the package changed /etc/sudoers"
[ ! -f /etc/sudoers.d/50-cardinal ] \
    || fail "the package installed a sudoers file; only the agent writes that"
echo "  unchanged, and no drop-in written"

echo "== the unit is installed and not enabled"
# Enabling it would start a daemon on a machine that has not enrolled, as a side
# effect of an install somebody may have done to read the manual.
if systemctl is-enabled cardinal-agent 2>/dev/null | grep -q '^enabled'; then
    fail "the package enabled the unit"
fi
echo "  installed, not enabled"

echo "== the binary runs"
/usr/bin/cardinal-agent help >/dev/null 2>&1 || fail "the installed binary does not run"
echo "  $(/usr/bin/cardinal-agent help 2>&1 | head -1)"

echo "== doctor says what is missing rather than guessing"
printf 'server = "https://id.example"\n' > /etc/cardinal/agent.toml
got=$(cardinal-agent doctor 2>&1 || true)
echo "$got" | sed 's/^/  /'
case "$got" in
    *enrolled*) ;;
    *) fail "doctor did not mention enrollment" "$got" ;;
esac
case "$got" in
    *"sudoers include"*) ;;
    *) fail "doctor did not mention the sudoers include" "$got" ;;
esac
if cardinal-agent doctor >/dev/null 2>&1; then
    fail "doctor exited 0 on a machine that has not enrolled"
fi
echo "  correctly non-zero while something fatal is outstanding"

echo "== and passes once the machine is prepared"
echo "@includedir /etc/sudoers.d" >> /etc/sudoers
mkdir -p /etc/cardinal && touch /etc/cardinal/host_key
mkdir -p /run/systemd/userdb && touch /run/systemd/userdb/io.systemd.Cardinal
got=$(cardinal-agent doctor 2>&1 || true)
echo "$got" | sed 's/^/  /'
case "$got" in
    *Ready*) ;;
    *) fail "doctor still reports problems on a prepared machine" "$got" ;;
esac

echo "== removing the package keeps its configuration"
apt-get remove -y cardinal-agent >/dev/null 2>&1
[ -f /etc/cardinal/agent.toml ] || fail "removing the package deleted its configuration"
[ ! -f /usr/bin/cardinal-agent ] || fail "the binary survived removal"
echo "  binary gone, /etc/cardinal/agent.toml kept"

echo
echo "PASS: the package installs, writes only its own paths, ships no maintainer"
echo "      scripts, and leaves the existing directory winning on nsswitch.conf"
