SHELL := /bin/bash
PSQL  := docker exec -i cardinal-postgres psql -U cardinal -d cardinal -v ON_ERROR_STOP=1
DSN   ?= postgres://cardinal:cardinal@localhost:5433/cardinal?sslmode=disable

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
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
	@# resetting a database they should have reset.
	@printf 'This destroys every account, credential and audit record in\n%s\n\nType "yes" to continue: ' '$(DSN)'
	@read -r reply && [ "$$reply" = yes ] || { echo 'aborted'; exit 1; }
	docker compose down -v
	@$(MAKE) --no-print-directory up
	@$(MAKE) --no-print-directory migrate
	@CARDINAL_DSN="$(DSN)" ./bin/cardinal policy publish policies/cardinal.cedar \
		-description 'development default' -activate | sed 's/^/  /'
	@CARDINAL_DSN="$(DSN)" ./bin/cardinal user create '$(ADMIN)' >/dev/null
	@CARDINAL_DSN="$(DSN)" ./bin/cardinal grant directory-admins '$(ADMIN)' \
		-reason 'founding admin' >/dev/null
	@echo
	@echo '==> start the server, then open this to register a passkey:'
	@CARDINAL_DSN="$(DSN)" ./bin/cardinal invite '$(ADMIN)' 2>/dev/null

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
	go test ./... -race -count=1

.PHONY: lint
lint: ## Run linters and vulnerability scanning
	gofumpt -l -d .
	go vet ./...
	golangci-lint run
	govulncheck ./...

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

.PHONY: e2e-up
e2e-up: ## Build and start the end-to-end stack (Traefik + a protected app)
	docker compose -f examples/compose.yml up -d --build
	@printf 'waiting for the stack'
	@for i in $$(seq 1 90); do \
		if curl -sf -H 'Host: id.localhost' http://127.0.0.1:8100/api/health >/dev/null 2>&1; then \
			echo ' ready'; break; fi; printf '.'; sleep 1; done
	@$(MAKE) --no-print-directory e2e-seed
	@echo '==> http://app.localhost:8100 (forwardAuth)  ·  http://client.localhost:8100 (OIDC)'
	@echo '    http://id.localhost:8100 (Cardinal)'

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
	@if ! $(COMPOSE_E2E) exec -T cardinal cardinal app list 2>/dev/null | grep -q e2e-client; then \
		$(COMPOSE_E2E) exec -T cardinal cardinal app register e2e-client \
			-display 'End-to-end relying party' \
			-redirect 'http://client.localhost:8100/callback' \
			-dev-mode \
			-scopes 'openid,profile,email,groups,offline_access' \
			-config /etc/cardinal/cardinal.toml >/dev/null; \
	fi
	@# Named explicitly. Tests register clients of their own, so `LIMIT 1` would
	@# hand the relying party whichever client the planner happened to return —
	@# and the failure would look like a redirect-URI mismatch, not a seeding bug.
	@$(COMPOSE_E2E) exec -T postgres psql -U cardinal -d cardinal -tAc \
		"SELECT c.client_id FROM oidc_clients c JOIN entities e ON e.id = c.entity_id \
		 WHERE e.name = 'e2e-client'" | tr -d ' \r\n' > examples/.oidc-client-id
	@OIDC_CLIENT_ID="$$(cat examples/.oidc-client-id)" $(COMPOSE_E2E) up -d oidc-client >/dev/null
	@echo "  relying party registered: $$(cut -c1-16 examples/.oidc-client-id)…"

.PHONY: e2e
e2e: ## Run the end-to-end tests against the running stack
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
