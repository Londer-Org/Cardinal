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
reset: ## Destroy the database and recreate it from migrations
	docker compose down -v
	$(MAKE) up
	$(MAKE) migrate

.PHONY: migrate
migrate: ## Apply all migrations in order
	@for f in migrations/*.sql; do \
		echo "--> $$f"; \
		$(PSQL) -f - < "$$f" > /dev/null || exit 1; \
	done
	@echo "migrations applied"

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
