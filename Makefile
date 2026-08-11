SHELL := /bin/bash
PSQL  := docker exec -i cardinal-postgres psql -U cardinal -d cardinal -v ON_ERROR_STOP=1
PYTHON ?= python3

# The release this tree is. One file, read by everything.
VERSION := $(shell cat VERSION)

# Where the example stack listens.
#
# Overridable because 8443 is a popular port and a laptop running anything else
# on it silently loses the race — whichever binds last wins, and the loser keeps
# running unreachable. Everything that dials the stack reads this, including the
# end-to-end suite, so overriding it moves the whole thing rather than half.
#
#     make e2e-up CARDINAL_PORT=8643
CARDINAL_PORT      ?= 8443
CARDINAL_HTTP_PORT ?= 8100
export CARDINAL_PORT
export CARDINAL_HTTP_PORT

CARDINAL_URL = https://id.cardinal.test:$(CARDINAL_PORT)
DSN   ?= postgres://cardinal:cardinal@localhost:5433/cardinal?sslmode=disable

.PHONY: help
help:
	@# Digits included, or every e2e-* target is invisible here — which they
	@# were, silently, for as long as this target has existed.
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

.PHONY: up
up: ## Start the PostgreSQL 19 development database
	docker compose up -d
	@printf 'waiting for postgres'
	@for i in $$(seq 1 60); do \
		if [ "$$(docker inspect -f '{{.State.Health.Status}}' cardinal-postgres 2>/dev/null)" = healthy ]; then \
			echo ' ready'; exit 0; fi; printf '.'; sleep 1; done; \
		echo ' TIMED OUT'; exit 1

.PHONY: down
down: ## Stop the database (keeps data)
	docker compose down

.PHONY: reset
reset: ## Destroy the dev database and recreate it with a first administrator
	@# For when the development database has filled up with experiments.
	@#
	@# Tests never need this. The store suite gets a fresh container per run via
	@# testcontainers, and the end-to-end stack has its own database in
	@# examples/compose.yml — so a run of `go test ./...` touches neither this
	@# database nor anything in it. What lands here is manual poking, which has
	@# nowhere else to go.
	@#
	@# It leaves you able to sign in, which the previous version did not: a
	@# migrated database with no accounts is one nobody can reach, and working
	@# that out from scratch each time is exactly the friction that stops people
	@# resetting a database they should have reset. The setup itself is
	@# `cardinal init`, so this and a real first run take the same path.
	@printf 'This destroys every account, credential and audit record in\n%s\n\nType "yes" to continue: ' '$(DSN)'
	@read -r reply && [ "$$reply" = yes ] || { echo 'aborted'; exit 1; }
	docker compose down -v
	@$(MAKE) --no-print-directory up
	@$(MAKE) --no-print-directory migrate
	@CARDINAL_DSN="$(DSN)" ./bin/cardinal init '$(ADMIN)'

# Who `make reset` makes an administrator. Override with `make reset ADMIN=you`.
ADMIN ?= $(USER)

.PHONY: migrate
migrate: build ## Apply the schema (same code path as a deployed container)
	@CARDINAL_DSN="$(DSN)" ./bin/cardinal migrate

.PHONY: psql
psql: ## Open a psql shell against the dev database
	docker exec -it cardinal-postgres psql -U cardinal -d cardinal

.PHONY: test
test: ## Run unit and integration tests
	@# Everything except test/e2e, which needs the example stack running and has
	@# `make e2e` of its own. Its TestMain exits 1 with "the stack is not
	@# running" rather than skipping — deliberately, so somebody running it by
	@# hand is told what to do — which means `go test ./...` cannot pass on a
	@# clean checkout. CI has excluded it from the start; this target did not,
	@# so the README's own five-line quickstart ended in a failure.
	go test ./internal/... ./cmd/... ./migrations/... -race -count=1

.PHONY: schema
schema: ## Regenerate docs/schema.md from the running database
	@go run ./tools/schemadoc
	@echo "==> docs/schema.md regenerated from the live schema"

.PHONY: schema-check
schema-check: ## Fail if docs/schema.md no longer matches the database
	@go run ./tools/schemadoc -check
	@echo "==> docs/schema.md matches the live schema"

.PHONY: package
package: ## Build .deb and .rpm for cardinal-agent (a snapshot, unsigned)
	@# --snapshot because there is no tag: this is for looking at and for
	@# verify-package, not for publishing.
	goreleaser release --snapshot --clean --skip=archive

.PHONY: ui-contrast
ui-contrast: ## Check every admin page reads, in both themes, against a real browser
	@# Needs the end-to-end stack and a chromium. See tools/uishot/README.md —
	@# including the two bugs this tool had, which are the reason it prints what
	@# it could not measure rather than counting it as a pass.
	@tools/uishot/check-contrast.sh

.PHONY: verify-package
verify-package: package ## Install the real .deb in a container and check what it did
	@# Building a package proves it builds. This proves it installs on a machine
	@# that has never heard of Cardinal, ships no maintainer scripts of its own,
	@# and leaves an existing directory winning on nsswitch.conf — so installing
	@# it is not a cutover.
	@docker build -q -f tools/hostcheck/package.Dockerfile \
		--build-arg DEB="$$(ls dist/cardinal-agent_*_linux_amd64.deb | head -1)" \
		-t cardinal-packagecheck . >/dev/null
	@docker run --rm cardinal-packagecheck

.PHONY: verify-passkey
verify-passkey: ## Register a passkey and sign in with it, in a real browser
	@# The Phase 1 check the plan asks for and nothing could run until now:
	@# WebAuthn needs a secure context, and the stack could not offer one while
	@# its hostnames were the only ones that could not also carry the
	@# parent-domain cookie single sign-on needs.
	@#
	@# Chrome's virtual authenticator makes the ceremony real in every respect
	@# except the hardware — the browser checks the origin against the relying
	@# party and signs, and Cardinal verifies it exactly as it would a YubiKey.
	@$(COMPOSE_E2E) exec -T cardinal cardinal user create passkey-check \
		-display 'Passkey Check' >/dev/null 2>&1 || true
	@invite=$$($(COMPOSE_E2E) exec -T cardinal cardinal invite passkey-check 2>&1 \
		| grep -oE 'https://[^ ]+' | head -1); \
	[ -n "$$invite" ] || { echo 'could not issue an invitation'; exit 1; }; \
	$(PYTHON) tools/uishot/verify-passkey.py --invite "$$invite" --login passkey-check

.PHONY: verify-acme
verify-acme: ## Drive the ACME server with lego, a client nobody here wrote
	@# The only check that says an implementation from outside this project will
	@# talk to Cardinal, which is the whole claim of ADR 0023. Everything else is
	@# Cardinal agreeing with Cardinal.
	@tools/acmecheck/check.sh

.PHONY: verify-rollback
verify-rollback: ## Run published releases against a schema this build migrated
	@# The upgrade story rests on one promise — migrations are expand-only, so
	@# rolling back is redeploying the old image and nothing else. The rule is
	@# enforced per migration by `go test ./migrations/`, and the drift logic is
	@# unit-tested against synthetic rows, but the pairing itself was only ever
	@# checked by reading. This runs it.
	@#
	@# Needs the published images, so it is not part of `make test`. Pass
	@# versions to override the default set.
	@bash tools/rollbackcheck/check.sh $(VERSIONS)

.PHONY: verify-host
verify-host: ## Check the host integration against real getent, id and sudo
	@# The Go tests prove each package agrees with a client written from the
	@# same reading of the specification, which is the trap this project has
	@# walked into before. This asks the system tools instead — and in
	@# particular asks sudo about a user who exists only in the varlink
	@# provider, which is the one question that spans both halves.
	@docker build -q -f tools/hostcheck/Dockerfile -t cardinal-hostcheck . >/dev/null
	@docker run --rm cardinal-hostcheck

# Pinned, and the same value CI uses. A local golangci-lint one minor version
# behind reported a clean tree while CI found five gosec issues the older build
# had no rules for, which is the worst way for a gate to fail: silently, and
# only after a push.
GOLANGCI_VERSION := v2.12.2
GOLANGCI := $(shell go env GOPATH)/bin/golangci-lint

GOVULNCHECK := $(shell go env GOPATH)/bin/govulncheck

.PHONY: lint-tools
lint-tools: ## Install the pinned linter and govulncheck if they are missing or stale
	@$(GOLANGCI) version 2>/dev/null | grep -q '$(GOLANGCI_VERSION:v%=%)' || { \
		echo "installing golangci-lint $(GOLANGCI_VERSION)"; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION); }
	@test -x $(GOVULNCHECK) || { echo "installing govulncheck"; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; }

.PHONY: lint
lint: lint-tools ## Run linters and vulnerability scanning
	gofumpt -l -d .
	go vet ./...
	$(GOLANGCI) run
	$(GOVULNCHECK) ./...

.PHONY: ui
ui: ## Build the admin UI into web/dist (embedded by the Go build)
	cd web && npm ci --silent && npm run build
	@# vite empties dist, taking the placeholder with it. Without one, a clean
	@# checkout fails to compile with "pattern all:dist: no matching files
	@# found" — an error that points at embed.go and not at the actual cause.
	@$(MAKE) --no-print-directory ui-placeholder

.PHONY: ui-placeholder
ui-placeholder:
	@git show HEAD:web/dist/.gitkeep > web/dist/.gitkeep 2>/dev/null || \
		echo 'Keeps //go:embed all:dist compiling before the UI is built.' > web/dist/.gitkeep

.PHONY: ui-check
ui-check: ## Typecheck and lint the frontend
	cd web && npx tsc --noEmit && npx eslint . --max-warnings 0

.PHONY: build
build: ## Build the cardinal binary (run `make ui` first for the admin UI)
	go build -o bin/cardinal ./cmd/cardinal

.PHONY: release
release: ui build ## Build the UI and a binary containing it
	@echo "==> single self-contained binary at bin/cardinal"

.PHONY: serve
serve: build ## Run the server in development mode
	./bin/cardinal serve -config cardinal.toml -dev

.PHONY: version
version: ## Print the version this tree builds
	@echo $(VERSION)

.PHONY: version-file
version-file: ## Regenerate internal/version from VERSION
	@# A constant rather than an ldflag, because Go discards an -X for a symbol
	@# that does not exist and says nothing about it. .goreleaser.yaml passed
	@# `-X main.version` to exactly such a symbol, so every release binary
	@# carried no version at all and nothing noticed — there was no `cardinal
	@# version` to notice with.
	@sed -i.bak 's|^const Number = ".*"$$|const Number = "$(VERSION)"|' \
		internal/version/version.go && rm -f internal/version/version.go.bak
	@grep -q 'const Number = "$(VERSION)"' internal/version/version.go \
		|| { echo 'version-file did not take effect'; exit 1; }
	@echo "  internal/version/version.go is $(VERSION)"

.PHONY: bump-patch bump-minor bump-major
bump-patch: ## Bump the patch version, regenerate, commit and tag
	@$(MAKE) --no-print-directory bump PART=patch
bump-minor: ## Bump the minor version, regenerate, commit and tag
	@$(MAKE) --no-print-directory bump PART=minor
bump-major: ## Bump the major version, regenerate, commit and tag
	@$(MAKE) --no-print-directory bump PART=major

.PHONY: bump
bump:
	@# Refuses on a dirty tree. A bump commit that swept up unrelated changes
	@# would put them in a release nobody reviewed, and the tag would point at
	@# something other than what was tested.
	@git diff --quiet && git diff --cached --quiet \
		|| { echo 'working tree is dirty — commit or stash first'; exit 1; }
	@current=$$(cat VERSION); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	patch=$$(echo $$current | cut -d. -f3); \
	case "$(PART)" in \
		major) major=$$((major + 1)); minor=0; patch=0 ;; \
		minor) minor=$$((minor + 1)); patch=0 ;; \
		patch) patch=$$((patch + 1)) ;; \
		*) echo 'PART must be major, minor or patch'; exit 1 ;; \
	esac; \
	next="$$major.$$minor.$$patch"; \
	echo "$$next" > VERSION; \
	$(MAKE) --no-print-directory version-file VERSION=$$next; \
	git add VERSION internal/version/version.go; \
	git commit -q -m "Release $$next"; \
	git tag -a "v$$next" -m "v$$next"; \
	echo; \
	echo "  $$current -> $$next, committed and tagged v$$next"; \
	echo "  push it to release:  git push && git push origin v$$next"

.PHONY: hosts-line
hosts-line: ## Print only the /etc/hosts entry, for scripting
	@# Its own target so a caller can pipe it. `make hosts | head -1` gives make
	@# a broken pipe and a non-zero exit, which in CI is a failed step reporting
	@# nothing useful.
	@echo '127.0.0.1  id.cardinal.test app.cardinal.test client.cardinal.test open.cardinal.test events.cardinal.test'

.PHONY: hosts
hosts: ## Print the /etc/hosts line the example stack needs, and what to do with it
	@$(MAKE) --no-print-directory hosts-line
	@echo
	@echo '  Add that to /etc/hosts, or on Windows to'
	@echo '  C:/Windows/System32/drivers/etc/hosts (backslashes there).'
	@echo '  .test is reserved by IANA for exactly this, so it resolves nowhere else'
	@echo '  and needs no DNS server.'

.PHONY: e2e-check
e2e-check: ## Check the one-time setup the example stack needs
	@# Two prerequisites, both one-time, both with a specific fix. Checked here
	@# rather than left to fail inside the stack, because "connection refused"
	@# and "certificate error" are a long way from "add a line to /etc/hosts".
	@ok=1; \
	if ! getent hosts id.cardinal.test >/dev/null 2>&1; then \
		echo 'id.cardinal.test does not resolve.'; \
		echo '  Run `make hosts` and add the line it prints.'; \
		echo; ok=0; \
	fi; \
	if ! command -v mkcert >/dev/null 2>&1; then \
		echo 'mkcert is not installed.'; \
		echo '  Debian/Ubuntu:  sudo apt install mkcert libnss3-tools'; \
		echo '  macOS:          brew install mkcert'; \
		echo '  Then:           mkcert -install'; \
		echo; ok=0; \
	elif [ ! -f "$$(mkcert -CAROOT)/rootCA.pem" ]; then \
		echo 'mkcert has no local CA yet.'; \
		echo '  Run `mkcert -install` — it writes a CA into your trust store,'; \
		echo '  and `mkcert -uninstall` takes it back out.'; \
		echo; ok=0; \
	fi; \
	[ "$$ok" = 1 ] || { \
		echo 'The stack needs both. Why, briefly:'; \
		echo; \
		echo '  Passkeys need a secure context, and the only plain-http origins'; \
		echo '  browsers trust are localhost, 127.0.0.1 and *.localhost. Those are'; \
		echo '  exactly the names that cannot carry a parent-domain cookie, which'; \
		echo '  is what forwardAuth single sign-on runs on. Doing both at once'; \
		echo '  leaves one option: a real domain, over HTTPS, with a certificate'; \
		echo '  the browser trusts.'; \
		exit 1; }
	@echo 'setup looks right'

.PHONY: e2e-up
e2e-up: e2e-check ## Build and start the end-to-end stack (Traefik + a protected app)
	@# A certificate the browser actually trusts, from the local CA mkcert
	@# installed. Generated rather than committed: it is a certificate for a
	@# domain anybody can claim on their own machine, and committing a private
	@# key is a bad habit even when the key is worthless.
	@# Regenerated when it does not cover every name the stack serves. Traefik
	@# answers with its own self-signed default for a host the certificate omits,
	@# and the failure names an internal Traefik hostname rather than the missing
	@# one — which is a genuinely confusing half hour.
	@if [ -f examples/traefik/tls/cardinal.test.crt ] && \
	    ! openssl x509 -in examples/traefik/tls/cardinal.test.crt -noout -text 2>/dev/null \
	      | grep -q events.cardinal.test; then \
		rm -f examples/traefik/tls/cardinal.test.crt examples/traefik/tls/cardinal.test.key; \
		echo "  the TLS certificate predates events.cardinal.test — reissuing"; \
	fi
	@if [ ! -f examples/traefik/tls/cardinal.test.crt ]; then \
		mkdir -p examples/traefik/tls; \
		(cd examples/traefik/tls && mkcert \
			-cert-file cardinal.test.crt -key-file cardinal.test.key \
			id.cardinal.test app.cardinal.test client.cardinal.test \
			open.cardinal.test events.cardinal.test cardinal.test) 2>/dev/null; \
		echo "  issued a TLS certificate for *.cardinal.test"; \
	fi
	@# The root, for workloads inside the network. A container inherits nothing
	@# from the host's trust store, so the OIDC relying party needs this to
	@# verify Cardinal at all — the same work every workload needs against an
	@# internal CA, and the part `cardinal x509 ca init` warns takes the time.
	@cp -f "$$(mkcert -CAROOT)/rootCA.pem" examples/traefik/tls/local-ca.pem
	docker compose -f examples/compose.yml up -d --build
	@# Loudly, and only when it is Cardinal answering.
	@#
	@# This loop used to fall through after ninety attempts and carry on to
	@# seeding, so a stack that never came up reported success and the failure
	@# surfaced much later as something else. Worse on a machine running other
	@# things: whatever binds :8443 last wins it, so the readiness probe can be
	@# answered by an unrelated service — and the end-to-end suite dials the
	@# same port, which would make it test that service instead.
	@#
	@# Checking the health endpoint specifically is what distinguishes "Cardinal
	@# is up" from "something is listening".
	@printf 'waiting for the stack'
	@ready=0; \
	for i in $$(seq 1 90); do \
		if curl -sf --resolve id.cardinal.test:$(CARDINAL_PORT):127.0.0.1 \
			$(CARDINAL_URL)/api/health >/dev/null 2>&1; then \
			echo ' ready'; ready=1; break; fi; printf '.'; sleep 1; done; \
	if [ "$$ready" = 0 ]; then \
		echo; \
		echo 'the stack never answered on $(CARDINAL_URL)'; \
		echo; \
		holder=$$(docker ps --format '{{.Names}}\t{{.Ports}}' | grep ':$(CARDINAL_PORT)->' \
			| grep -v cardinal-e2e | cut -f1); \
		if [ -n "$$holder" ]; then \
			echo "  $$holder is bound to port $(CARDINAL_PORT)."; \
			echo '  Whatever binds it last wins, so Cardinal may be running and'; \
			echo '  unreachable — and `make e2e` dials the same port, which would'; \
			echo '  point the whole suite at that container instead.'; \
		else \
			echo '  docker compose -f examples/compose.yml logs cardinal traefik'; \
			echo '  and check `make e2e-check` for the one-time setup.'; \
		fi; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory e2e-seed
	@echo '==> https://app.cardinal.test:$(CARDINAL_PORT) (forwardAuth)  ·  https://client.cardinal.test:$(CARDINAL_PORT) (OIDC)'
	@echo '    $(CARDINAL_URL) (Cardinal)'

COMPOSE_E2E := docker compose -f examples/compose.yml

.PHONY: e2e-seed
e2e-seed: ## Create the end-to-end user and activate the policy set
	@# Errors are NOT swallowed here. An earlier version used `|| true`, and a
	@# failed user creation then surfaced much later as a confusing
	@# "session invalid" much later, from a seeded session pointing at nothing.
	@$(COMPOSE_E2E) exec -T cardinal \
		cardinal user create e2e-user -display 'End-to-end User' 2>&1 \
		| grep -qE 'created|already exists' \
		|| { echo 'ERROR: could not create e2e-user'; \
		     $(COMPOSE_E2E) exec -T cardinal cardinal user create e2e-user; exit 1; }
	@docker cp policies/cardinal.cedar \
		"$$($(COMPOSE_E2E) ps -q cardinal)":/tmp/cardinal.cedar
	@$(COMPOSE_E2E) exec -T cardinal \
		cardinal policy publish /tmp/cardinal.cedar -description 'e2e stack' -activate \
		| sed 's/^/  /'
	@# The application behind Traefik, and the hostname it answers to.
	@#
	@# forwardAuth is handed a hostname and resolves it to an application, whose
	@# group membership decides who may reach it. Without these three commands
	@# every request to app.cardinal.test is refused before policy is consulted
	@# — which is the correct answer for an address nobody registered, and is
	@# what the stack looked like before this existed.
	@$(COMPOSE_E2E) exec -T cardinal \
		cardinal application create protected-app -display 'Protected App' 2>&1 \
		| grep -qE 'created|already exists' \
		|| { echo 'ERROR: could not create the protected application'; exit 1; }
	@$(COMPOSE_E2E) exec -T cardinal \
		cardinal app hostname add protected-app app.cardinal.test 2>&1 \
		| grep -qE 'answers for|already holds' \
		|| { echo 'ERROR: could not register app.cardinal.test'; exit 1; }
	@# Into staff-apps, which is what the shipped staff-web-access rule permits.
	@# Empty on a fresh install on purpose: registering an application makes it
	@# findable, and this is the deliberate act that makes it reachable.
	@$(COMPOSE_E2E) exec -T cardinal \
		cardinal grant staff-apps protected-app 2>&1 \
		| grep -qE 'granted|already' \
		|| { echo 'ERROR: could not put protected-app in staff-apps'; exit 1; }
	@# And told about every group, which is what this fixture assumed before
	@# projections existed (ADR 0032). An application created now starts in
	@# `owned` mode and owns nothing, so the identity headers arrive with no
	@# groups at all — which is correct, and broke the header tests the moment
	@# the default changed.
	@#
	@# Set here rather than by narrowing those tests: they are about whether a
	@# stable identifier reaches an application, and coupling them to a
	@# disclosure setting would make a failure ambiguous. The projection has an
	@# end-to-end test of its own that flips this deliberately.
	@$(COMPOSE_E2E) exec -T cardinal \
		cardinal app groups mode protected-app all 2>&1 \
		| grep -qE 'every group' \
		|| { echo 'ERROR: could not widen the group projection'; exit 1; }
	@# The Shared Signals receiver, which is deliberately not Cardinal: it
	@# fetches the JWKS like any receiver would and verifies what arrives. The
	@# stream is configured here because stream management over the API is not
	@# implemented, and the SSF configuration document says so.
	@# Registered as a relying party rather than created as a bare application:
	@# a stream's audience is an OIDC client id, so the receiver needs one. Its
	@# redirect URI is never used — nobody signs in to a receiver.
	@$(COMPOSE_E2E) exec -T cardinal \
		cardinal app register ssf-receiver \
		-redirect https://events.cardinal.test/unused 2>&1 \
		| grep -qE 'client_id|already exists' \
		|| { echo 'ERROR: could not register the receiver'; \
		     $(COMPOSE_E2E) exec -T cardinal cardinal app register ssf-receiver \
		       -redirect https://events.cardinal.test/unused; exit 1; }
	@$(COMPOSE_E2E) exec -T cardinal \
		cardinal ssf stream add ssf-receiver \
		-endpoint https://events.cardinal.test:$(CARDINAL_PORT)/events >/dev/null 2>&1 \
		|| { echo 'ERROR: could not configure the signals stream'; exit 1; }
	@# An authority key, so host certificates can be issued. -activate because
	@# nothing in the stack trusts an older key: the careful two-step ordering
	@# exists for a fleet that already has one, and there is no fleet here.
	@# Guarded from out here: the image is distroless, so there is no shell in
	@# the container to put the conditional in.
	@if ! $(COMPOSE_E2E) exec -T cardinal cardinal ssh ca list 2>/dev/null | grep -q signing; then \
		$(COMPOSE_E2E) exec -T cardinal cardinal ssh ca init -activate \
			-config /etc/cardinal/cardinal.toml >/dev/null; \
		echo "  SSH certificate authority created"; \
	fi
	@# An X.509 authority, so ACME can issue. -activate for the same reason as
	@# the SSH one: nothing in this stack trusts an older key.
	@if ! $(COMPOSE_E2E) exec -T cardinal cardinal x509 ca list 2>/dev/null | grep -q signing; then \
		$(COMPOSE_E2E) exec -T cardinal cardinal x509 ca init -activate \
			-subject 'Cardinal end-to-end CA' \
			-config /etc/cardinal/cardinal.toml >/dev/null 2>&1; \
		echo "  X.509 certificate authority created"; \
	fi
	@# The server loads policy at startup, so it has to be restarted to pick up
	@# the version just activated.
	@$(COMPOSE_E2E) restart cardinal >/dev/null
	@sleep 4
	@$(MAKE) --no-print-directory e2e-seed-oidc

.PHONY: e2e-seed-oidc
e2e-seed-oidc: ## Register the relying party and start it with its client id
	@# The client id is generated, so the relying party cannot be configured
	@# until Cardinal has issued one. Registering first and starting the client
	@# after is the only ordering that works.
	@# Re-registered when the redirect URI no longer matches, not merely when
	@# the client is absent.
	@#
	@# The registration is persistent state that embeds the port, so overriding
	@# CARDINAL_PORT against an existing database left a client whose registered
	@# URI pointed at the old one. Every authorization then failed with a
	@# redirect-URI mismatch — correctly, and looking nothing like a stale
	@# fixture.
	@want='https://client.cardinal.test:$(CARDINAL_PORT)/callback'; \
	have=$$($(COMPOSE_E2E) exec -T postgres psql -U cardinal -d cardinal -tAc \
		"SELECT coalesce(array_to_string(c.redirect_uris, ','), '') \
		   FROM oidc_clients c JOIN entities e ON e.id = c.entity_id \
		  WHERE e.name = 'e2e-client'" 2>/dev/null | tr -d ' \r\n'); \
	if [ -z "$$have" ]; then \
		$(COMPOSE_E2E) exec -T cardinal cardinal app register e2e-client \
			-display 'End-to-end relying party' \
			-redirect "$$want" \
			-dev-mode \
			-scopes 'openid,profile,email,groups,offline_access' \
			-config /etc/cardinal/cardinal.toml >/dev/null; \
	elif [ "$$have" != "$$want" ]; then \
		echo "  redirect URI was $$have — pointing it at $(CARDINAL_PORT)"; \
		$(COMPOSE_E2E) exec -T postgres psql -U cardinal -d cardinal -q -c \
			"UPDATE oidc_clients SET redirect_uris = ARRAY['$$want'] \
			  WHERE entity_id = (SELECT id FROM entities \
			                      WHERE type = 'application' AND name = 'e2e-client')" \
			>/dev/null; \
	fi
	@# Named explicitly. Tests register clients of their own, so `LIMIT 1` would
	@# hand the relying party whichever client the planner happened to return —
	@# and the failure would look like a redirect-URI mismatch, not a seeding bug.
	@$(COMPOSE_E2E) exec -T postgres psql -U cardinal -d cardinal -tAc \
		"SELECT c.client_id FROM oidc_clients c JOIN entities e ON e.id = c.entity_id \
		 WHERE e.name = 'e2e-client'" | tr -d ' \r\n' > examples/.oidc-client-id
	@OIDC_CLIENT_ID="$$(cat examples/.oidc-client-id)" $(COMPOSE_E2E) up -d oidc-client >/dev/null
	@echo "  relying party registered: $$(cut -c1-16 examples/.oidc-client-id)…"

.PHONY: e2e-reset
e2e-reset: ## Drop the end-to-end database and rebuild it from migrations and seed
	@# A database the tests have never seen before.
	@#
	@# The suite is written to tolerate leftovers — the stack outlives a single
	@# `go test` run, so helpers re-register streams and re-create users rather
	@# than assuming a clean slate. That tolerance is what lets it be run twice,
	@# and it is also what let a real regression pass here and fail in CI: a
	@# migration had backfilled a setting on rows that already existed, while CI
	@# built the stack from nothing and got the new default. Both were correct;
	@# only one was being tested.
	@#
	@# Dropping the database rather than truncating it, because the schema is
	@# part of what drifts: a column added since the stack was last built is
	@# exactly the thing a TRUNCATE would preserve the absence of.
	@$(COMPOSE_E2E) exec -T postgres psql -U cardinal -d postgres -q 		-c "DROP DATABASE IF EXISTS cardinal WITH (FORCE)" 		-c "CREATE DATABASE cardinal OWNER cardinal" >/dev/null
	@$(COMPOSE_E2E) run --rm --no-deps cardinal migrate 		-dsn "postgres://cardinal:cardinal@postgres:5432/cardinal?sslmode=disable" 		| sed 's/^/  /'
	@# Restarted because it holds a connection pool to a database that no longer
	@# exists, and because the policy set is loaded at startup.
	@$(COMPOSE_E2E) up -d --force-recreate cardinal >/dev/null 2>&1
	@$(COMPOSE_E2E) exec -T cardinal /bin/sh -c 'exit 0' 2>/dev/null || sleep 8
	@$(MAKE) --no-print-directory e2e-seed
	@$(MAKE) --no-print-directory e2e-seed-oidc
	@echo "==> the end-to-end database is new"

.PHONY: e2e
e2e: e2e-reset ## Run the end-to-end tests against a freshly seeded stack
	@# Rate-limit counters are cleared first, so the suite is repeatable.
	@#
	@# Several tests deliberately spend failed attempts — redeeming a recovery
	@# code with the wrong code is the point of one of them — and the limiter
	@# has no idea it is being tested. Run twice in a row without this and the
	@# second run fails with 429s that look like a bug in what is being tested
	@# rather than in the fixture, which cost an hour once.
	@#
	@# Deliberately not making the limits looser for the stack: the thing being
	@# exercised should be the one that ships.
	go test ./test/e2e/... -count=1 -v

.PHONY: e2e-keep
e2e-keep: ## Run the end-to-end tests without resetting, for a fast loop
	@# The old behaviour, kept because rebuilding the database between every
	@# attempt makes debugging one test tedious. Rate-limit counters are cleared
	@# because several tests deliberately spend failed attempts and the limiter
	@# has no idea it is being tested — run twice without this and the second
	@# run fails with 429s that look like a bug in what is being tested.
	@#
	@# What it cannot tell you is whether the thing you are testing works on a
	@# database that has not seen the previous twenty attempts. `make e2e` can.
	@$(COMPOSE_E2E) exec -T postgres \
		psql -U cardinal -d cardinal -q -c "TRUNCATE rate_limits" >/dev/null
	go test ./test/e2e/... -count=1 -v

.PHONY: e2e-down
e2e-down: ## Stop and remove the end-to-end stack
	docker compose -f examples/compose.yml down -v

.PHONY: restore-drill
restore-drill: build ## Back up, restore to a scratch DB, and verify the audit chain
	@echo "==> backing up"
	@docker exec cardinal-postgres pg_dump -U cardinal -d cardinal -Fc -f /tmp/cardinal.dump
	@echo "==> restoring into a scratch database"
	@docker exec cardinal-postgres psql -U cardinal -d postgres -q \
		-c "DROP DATABASE IF EXISTS cardinal_restore_drill" 2>/dev/null
	@docker exec cardinal-postgres psql -U cardinal -d postgres -q \
		-c "CREATE DATABASE cardinal_restore_drill"
	@docker exec cardinal-postgres pg_restore -U cardinal \
		-d cardinal_restore_drill /tmp/cardinal.dump
	@echo "==> verifying the restored audit chain"
	@CARDINAL_DSN="postgres://cardinal:cardinal@localhost:5433/cardinal_restore_drill?sslmode=disable" \
		./bin/cardinal audit verify
	@docker exec cardinal-postgres psql -U cardinal -d postgres -q \
		-c "DROP DATABASE cardinal_restore_drill"
	@echo "==> restore drill passed"

# An untested backup is not a backup. This drill belongs on a schedule, not in
# an incident: a plain pg_restore proves the data came back, but verifying the
# hash chain proves it came back *unaltered* — which is the question that
# actually matters after a compromise.
