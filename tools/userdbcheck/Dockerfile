# Verifies the varlink provider against the real nss-systemd.
#
# A container rather than the developer's machine because this writes a socket
# into /run/systemd/userdb and edits nsswitch.conf — both root-owned, both
# things a test has no business doing to somebody's laptop.
FROM golang:1.25-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/userdbcheck ./tools/userdbcheck

FROM debian:trixie-slim
# libnss-systemd is the whole point: it is the client whose opinion matters.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libnss-systemd \
 && rm -rf /var/lib/apt/lists/*

# nss-systemd is consulted only if nsswitch.conf names it. On a real host this
# is what the .deb would do.
RUN sed -i 's/^passwd:.*/passwd:         files systemd/; s/^group:.*/group:          files systemd/' \
        /etc/nsswitch.conf

COPY --from=build /out/userdbcheck /usr/local/bin/userdbcheck
COPY tools/userdbcheck/verify.sh /usr/local/bin/verify.sh
RUN chmod +x /usr/local/bin/verify.sh
ENTRYPOINT ["/usr/local/bin/verify.sh"]
