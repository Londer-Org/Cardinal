# Installs the real .deb and checks what it did and did not do.
#
# Building a package proves it builds. This proves it installs on a machine that
# has never heard of Cardinal, puts its files where the unit expects them, ships
# no maintainer scripts of its own, and — the part worth checking hardest —
# leaves an existing directory winning on nsswitch.conf, so installing it is not
# a cutover.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends sudo openssh-server \
 && rm -rf /var/lib/apt/lists/*

ARG DEB
COPY ${DEB} /tmp/cardinal-agent.deb
COPY tools/hostcheck/verify-package.sh /usr/local/bin/verify-package.sh
RUN chmod +x /usr/local/bin/verify-package.sh
ENTRYPOINT ["/usr/local/bin/verify-package.sh"]
