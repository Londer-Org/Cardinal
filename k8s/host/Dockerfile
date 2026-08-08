# A Linux server that gets its identity from the Cardinal running in Kubernetes.
#
# The piece the cluster stack cannot contain. `cardinal-agent` writes
# /etc/sudoers.d, serves a varlink socket nss-systemd must reach, and manages
# sshd's trust configuration — it belongs on a machine, not in the cluster it
# talks to. So this is a machine, and it reaches the cluster the way a VM in the
# same estate would.
#
# Distinct from tools/hostcheck, which runs the userdb server in-process and
# never speaks to a Cardinal at all. That one checks the host-side components
# agree with nss-systemd and sudo. This one checks they agree with a *server*:
# enrollment over the network, an assignment fetched from it, and a host
# certificate signed by its SSH authority.
#
# It installs the published .deb rather than building from source, so the thing
# under test is the artefact the release produced.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libnss-systemd sudo openssh-server openssh-client \
        ca-certificates curl jq \
 && rm -rf /var/lib/apt/lists/*

# nss-systemd is the supported modern replacement for nss_ldap, and the reason
# there is no C NSS module in this project. Without this line getent never asks
# the agent anything.
RUN sed -i 's/^passwd:.*/passwd:         files systemd/; s/^group:.*/group:          files systemd/' \
        /etc/nsswitch.conf

# Host keys, so the certificate signed at run time is for a key that exists.
RUN ssh-keygen -A

# The local CA, so this machine trusts the certificate Traefik presents. A
# container inherits nothing from the host's trust store — the same work every
# machine needs against an internal CA.
COPY local-ca.pem /usr/local/share/ca-certificates/cardinal-local-ca.crt
RUN update-ca-certificates

ARG AGENT_DEB=cardinal-agent.deb
COPY ${AGENT_DEB} /tmp/cardinal-agent.deb
RUN dpkg -i /tmp/cardinal-agent.deb && rm /tmp/cardinal-agent.deb

COPY join.sh /usr/local/bin/join.sh
RUN chmod +x /usr/local/bin/join.sh

ENTRYPOINT ["/usr/local/bin/join.sh"]
