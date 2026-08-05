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

.PHONY: build
build: ## Build the cardinal binary
	go build -o bin/cardinal ./cmd/cardinal
