# Verifies the host-side integration against the real thing.
#
# Two questions no Go test can answer, and the second is the one that matters:
#
#   1. Does nss-systemd accept the varlink provider's records?
#   2. Does *sudo* grant access to a user who exists only in that provider?
#
# The second is the whole integration. A sudoers rule naming `alice` is inert if
# sudo cannot resolve alice, and it resolves her through exactly the NSS path
# this image configures.
FROM golang:1.25-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/hostcheck ./tools/hostcheck

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libnss-systemd sudo \
 && rm -rf /var/lib/apt/lists/*

RUN sed -i 's/^passwd:.*/passwd:         files systemd/; s/^group:.*/group:          files systemd/' \
        /etc/nsswitch.conf

COPY --from=build /out/hostcheck /usr/local/bin/hostcheck
COPY tools/hostcheck/verify.sh /usr/local/bin/verify.sh
RUN chmod +x /usr/local/bin/verify.sh
ENTRYPOINT ["/usr/local/bin/verify.sh"]
