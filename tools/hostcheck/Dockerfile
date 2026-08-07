# Verifies the host-side integration against the real thing.
#
# Two questions no Go test can answer, and the second is the one that matters:
#
#   1. Does nss-systemd accept the varlink provider's records?
#   2. Does *sudo* grant access to a user who exists only in that provider?
#   3. Does a real ssh client accept the host certificate without prompting?
#
# The second is the integration between the two halves — a sudoers rule naming
# `alice` is inert if sudo cannot resolve alice. The third is the claim the whole
# host-certificate feature rests on, and one that cannot be made by any Go test:
# whether trust-on-first-use is actually gone.
FROM golang:1.25-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/hostcheck ./tools/hostcheck

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libnss-systemd sudo openssh-server openssh-client \
 && rm -rf /var/lib/apt/lists/*

RUN sed -i 's/^passwd:.*/passwd:         files systemd/; s/^group:.*/group:          files systemd/' \
        /etc/nsswitch.conf

# Generated at build time so the certificate signed at run time is for a key
# that exists. Never leaves this image.
RUN ssh-keygen -A

COPY --from=build /out/hostcheck /usr/local/bin/hostcheck
COPY tools/hostcheck/verify.sh /usr/local/bin/verify.sh
RUN chmod +x /usr/local/bin/verify.sh
ENTRYPOINT ["/usr/local/bin/verify.sh"]
