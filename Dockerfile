# Cardinal ships as one self-contained binary: the admin UI is compiled by Vite
# and embedded via //go:embed, so there is no separate web server and no version
# skew between frontend and backend (ADR 0008).

# ── UI ──────────────────────────────────────────────────────────────────────
FROM node:22-alpine AS ui

WORKDIR /build/web
# Manifests first, so a source-only change does not invalidate the npm layer.
COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
# Typecheck and lint here as well as in CI: an image must never be built from
# code that would fail the gates. `any` is banned and no-unsafe-* are errors.
RUN npx tsc --noEmit && npx eslint . --max-warnings 0 && npx vite build

# ── Server ──────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS build

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Overwrite whatever web/dist the build context carried with the freshly built
# UI, so the embedded assets always match this build.
COPY --from=ui /build/web/dist ./web/dist

# CGO off for a static binary that runs on distroless. Symbols and DWARF
# stripped: they are of no use in production and add ~30% to the image.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/cardinal-server ./cmd/cardinal-server \
 && CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/cardinal ./cmd/cardinal

# ── Runtime ─────────────────────────────────────────────────────────────────
# distroless/static: no shell, no package manager, no libc. Nothing for an
# attacker who achieves execution to pivot with — which matters more here than
# in most images, since this process holds the keys to everything else.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

# The server, and deliberately not the administrative CLI.
#
# This image's entrypoint used to *be* that CLI, and the configuration it reads
# carries the connection string — so a shell in a running container was an
# unauthenticated administrator in one command, with nothing to discover:
#
#     $ cardinal list group        # no flags, no credential
#     group  directory-admins  ...
#
# What leaving it out buys, stated exactly: whoever holds the database
# credential still owns the directory, because psql exists and nothing here can
# prevent that. It raises the cost from "type the command you already know" to
# "know the credential and bring a tool", and it stops the running server from
# being the tool. A smaller claim than it looks, and the true one.
COPY --from=build /out/cardinal-server /usr/local/bin/cardinal-server

# Never root. The binary needs no privileged port and no filesystem writes.
USER nonroot:nonroot

EXPOSE 8080

# The image carries no configuration. cardinal.toml must be mounted and the
# break-glass public key set, or the server refuses to start — configuration
# with no safe default has no default (see internal/config).
ENTRYPOINT ["/usr/local/bin/cardinal-server"]
CMD ["serve", "-config", "/etc/cardinal/cardinal.toml"]

# Development and testing only, and never published.
#
# The end-to-end stack drives fixtures with the CLI, which needs the database
# and therefore cannot sign in from a container with no browser. Rather than
# invent a headless administrative path — the thing ADR 0033 exists to remove —
# the test stack gets an image that carries the tool and the published one does
# not.
FROM runtime AS tools
COPY --from=build /out/cardinal /usr/local/bin/cardinal

# Last, so it is what `docker build` produces without a target: what ships is
# the smaller thing, and asking for the larger one is deliberate.
FROM runtime AS server
