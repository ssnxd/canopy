SHELL := /bin/sh

GOCACHE ?= $(PWD)/.gocache
GO_TEST := GOCACHE="$(GOCACHE)" go test
GO_VET := GOCACHE="$(GOCACHE)" go vet
CANOPY_E2E_DATABASE_URL ?= postgres://postgres:postgres@localhost:5432/canopy_test?sslmode=disable
export CANOPY_E2E_DATABASE_URL

.PHONY: help test test-unit unit test-e2e e2e test-all test-race fmt-check vet vuln ci release-check release go-release check-e2e-db check-goreleaser check-github-token check-clean check-tag

help:
	@printf '%s\n' 'Targets:'
	@printf '  %-16s %s\n' 'test' 'Run unit tests'
	@printf '  %-16s %s\n' 'test-unit' 'Run unit tests'
	@printf '  %-16s %s\n' 'test-e2e' 'Run Postgres-backed e2e tests'
	@printf '  %-16s %s\n' 'test-all' 'Run unit and e2e tests'
	@printf '  %-16s %s\n' 'test-race' 'Run unit tests with the race detector'
	@printf '  %-16s %s\n' 'fmt-check' 'Check Go formatting'
	@printf '  %-16s %s\n' 'vet' 'Run go vet'
	@printf '  %-16s %s\n' 'vuln' 'Run govulncheck'
	@printf '  %-16s %s\n' 'ci' 'Run formatting, race, vet, and vulnerability checks'
	@printf '  %-16s %s\n' 'release-check' 'Run release validation without publishing'
	@printf '  %-16s %s\n' 'release' 'Publish the current v* tag with GoReleaser'

test: test-unit

unit: test-unit

test-unit:
	$(GO_TEST) ./...

e2e: test-e2e

test-e2e: check-e2e-db
	$(GO_TEST) -count=1 -tags=e2e ./...

test-all: test-unit test-e2e

test-race:
	$(GO_TEST) -race ./...

fmt-check:
	@test -z "$$(gofmt -l $$(git ls-files '*.go'))" || { \
		printf '%s\n' 'The following Go files need gofmt:' >&2; \
		gofmt -l $$(git ls-files '*.go') >&2; \
		exit 1; \
	}

vet:
	$(GO_VET) ./...

vuln:
	GOCACHE="$(GOCACHE)" go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

ci: fmt-check test-race vet vuln

release-check: test-all ci check-goreleaser
	goreleaser check
	goreleaser release --snapshot --clean

release: check-clean check-tag check-goreleaser check-github-token
	goreleaser release --clean

go-release: release

check-e2e-db:
	@test -n "$(CANOPY_E2E_DATABASE_URL)" || { \
		printf '%s\n' 'CANOPY_E2E_DATABASE_URL is required for e2e tests.' >&2; \
		printf '%s\n' 'Example: CANOPY_E2E_DATABASE_URL="postgres://user:pass@localhost:5432/canopy_test?sslmode=disable" make test-e2e' >&2; \
		exit 1; \
	}

check-goreleaser:
	@command -v goreleaser >/dev/null 2>&1 || { \
		printf '%s\n' 'goreleaser is required for this target.' >&2; \
		printf '%s\n' 'Install with: go install github.com/goreleaser/goreleaser/v2@v2.17.0' >&2; \
		exit 1; \
	}

check-github-token:
	@test -n "$(GITHUB_TOKEN)" || { \
		printf '%s\n' 'GITHUB_TOKEN is required to publish a GitHub release.' >&2; \
		exit 1; \
	}

check-clean:
	@test -z "$$(git status --porcelain)" || { \
		printf '%s\n' 'release requires a clean git worktree.' >&2; \
		git status --short >&2; \
		exit 1; \
	}

check-tag:
	@git describe --tags --exact-match --match 'v[0-9]*' >/dev/null 2>&1 || { \
		printf '%s\n' 'release must be run from a SemVer-style v* tag.' >&2; \
		exit 1; \
	}
