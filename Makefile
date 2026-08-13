# Stamped into every binary via internal/version. "dev" when unset, which is
# always visible and never a release — an empty string would vanish behind an
# omitempty tag and make a failed injection look like an old build.
VERSION ?= dev
LDFLAGS := -X github.com/griffithind/orbit/internal/version.Version=$(VERSION)

ADMIN_DSN ?= postgres://postgres:orbit@localhost:5433/orbit?sslmode=disable

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "%-14s %s\n", $$1, $$2}'

.PHONY: build
build: ## Build all packages
	go build -ldflags "$(LDFLAGS)" ./...

# The admin CLI, built on its own because it is the one binary that ships to
# somewhere other than the control plane host. It links neither internal/mesh
# nor the database driver, which is what keeps `go install ./cmd/orbit` from
# pulling in nebula and gvisor.
.PHONY: orbit
orbit: ## Build the admin CLI into ./bin/orbit
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/orbit ./cmd/orbit

# The exact matrix .github/workflows/release.yml ships, run locally. A target
# that only fails in CI after a tag is pushed is one that finds the breakage at
# the worst possible moment.
.PHONY: release-check
release-check: ## Cross-compile every release target without producing artifacts
	@set -e; \
	for t in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do \
		CGO_ENABLED=0 GOOS=$${t%/*} GOARCH=$${t#*/} \
			go build -o /dev/null ./cmd/orbit && echo "ok   orbit $$t"; \
	done; \
	for t in linux/amd64 linux/arm64; do \
		CGO_ENABLED=0 GOOS=$${t%/*} GOARCH=$${t#*/} \
			go build -o /dev/null ./cmd/orbitd && echo "ok   orbitd $$t"; \
	done

# Everything the release workflow checks, before a tag exists to check it.
.PHONY: release-ready
release-ready: ## Verify this tree could be released as the version the README pins
	@v=$$(./scripts/changelog-latest.sh); \
	echo "changelog describes $$v"; \
	./scripts/changelog-section.sh "$$v" > /dev/null && echo "changelog ok"; \
	./scripts/third-party-notices.sh > /dev/null; \
	git diff --quiet THIRD-PARTY-NOTICES.md && echo "notices ok" \
		|| { echo "notices STALE — commit the regenerated file"; exit 1; }; \
	$(MAKE) --no-print-directory release-check

.PHONY: third-party
third-party: ## Regenerate THIRD-PARTY-NOTICES.md from go.mod
	./scripts/third-party-notices.sh
	@echo "bin/orbit — set ORBIT_URL and ORBIT_TOKEN, then run: bin/orbit whoami"

.PHONY: test
test: ## Run all tests (store tests skip if Postgres is unreachable)
	go test ./... -count=1

.PHONY: test-v
test-v: ## Run all tests verbosely
	go test ./... -count=1 -v

# The host-state tests need root, a real kernel and a network namespace they can
# ruin, so they skip everywhere else. What they check was assumed correct once
# and was not, which is why they exist rather than a comment claiming it works.
#
# THE PACKAGE MATTERS, and it was wrong. This ran ./internal/agent/ while the
# tests live in ./internal/agent/hostcfg/ — the agent split moved them and this
# line did not follow. `go test` with a -run that matches nothing prints "no
# tests to run", exits 0, and reports ok: a gate that had been green while
# testing nothing.
#
# NO -run FILTER, for the same reason. A regex listing test names is a second
# place that has to be kept in sync with the tests, and it had already drifted
# once — adding the forwarding tests, three of the four did not match it. The
# whole package runs; everything in it that does not need root skips itself
# everywhere else, and in here nothing should skip at all, which the greps below
# now check. A gate that cannot report green on zero tests is the point.
.PHONY: test-netns
test-netns: ## Run the host-state tests on a real Linux kernel, in Docker
	docker run --rm --privileged -v "$(PWD)":/src -w /src golang:1.26-alpine \
		sh -c 'apk add -q iproute2 nftables iputils && \
		 go test ./internal/agent/hostcfg/ -count=1 -v 2>&1 | tee /tmp/netns.out; \
		 grep -q "no tests to run" /tmp/netns.out && { echo "ran nothing"; exit 1; }; \
		 grep -q "SKIP" /tmp/netns.out && { echo "skipped inside the container"; exit 1; }; \
		 grep -qE "^(ok|--- PASS)" /tmp/netns.out'

.PHONY: check
check: ## gofmt + vet + test
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt needed"; exit 1)
	go vet ./...
	go test ./... -count=1

# The other half of ADR-0007's quarterly rehearsal. check-break-glass proves the
# credential still works; this proves the backup still restores — and the
# failures it exists for are not "it stopped working" but things that were never
# going to work, every one of them found by reading rather than by trying.
.PHONY: check-restore
check-restore: ## Restore the backup into a scratch database and prove it opens
	@ORBIT_DSN="$$ORBIT_DSN" ORBITD="$${ORBITD:-go run ./cmd/orbitd}" \
		sh scripts/check-restore.sh

.PHONY: check-break-glass
check-break-glass: ## Verify the break-glass token still works (see docs/deployment.md 5)
	@ORBIT_BREAK_GLASS="$$ORBIT_BREAK_GLASS" ORBIT_URL="$${ORBIT_URL:-http://localhost:8080}" \
		sh scripts/check-break-glass.sh

.PHONY: db-up
db-up: ## Start the development Postgres and wait for it
	docker compose up -d --wait postgres

.PHONY: db-down
db-down: ## Stop and remove the development Postgres (destroys data)
	docker compose down -v

.PHONY: db-reset
db-reset: db-down db-up migrate ## Recreate the database from scratch

.PHONY: migrate
migrate: ## Apply migrations to $(ADMIN_DSN)
	go run ./cmd/orbitd migrate -dsn "$(ADMIN_DSN)"

.PHONY: psql
psql: ## Open a psql shell in the development database
	docker compose exec postgres psql -U postgres -d orbit

.PHONY: e2e
e2e: ## Run the end-to-end tests (needs Postgres)
	go test ./e2e/ -count=1 -v -timeout 300s

.PHONY: demo
demo: ## Bootstrap a local mesh and print next steps
	@go run ./cmd/orbitd bootstrap -dsn "$(ADMIN_DSN)"
