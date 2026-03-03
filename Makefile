.PHONY: all lint test integration conformance docker proto generate clean

GOFLAGS := -race
BINARY_AEGISD := bin/aegisd
BINARY_AEGISCTL := bin/aegisctl
PROTO_DIR := pkg/schema
PROTO_OUT_GO := pkg/schema

# ── default ────────────────────────────────────────────────────────────────────
all: proto generate lint test

# ── codegen ────────────────────────────────────────────────────────────────────
proto:
	@which protoc >/dev/null 2>&1 || (echo "ERROR: protoc not found; install protobuf-compiler" && exit 1)
	@which protoc-gen-go >/dev/null 2>&1 || go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@which protoc-gen-go-grpc >/dev/null 2>&1 || go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	protoc \
		--go_out=$(PROTO_OUT_GO) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_OUT_GO) --go-grpc_opt=paths=source_relative \
		-I $(PROTO_DIR) \
		$(PROTO_DIR)/events.proto \
		$(PROTO_DIR)/store.proto

generate:
	go generate ./...

# ── quality gates ───────────────────────────────────────────────────────────────
lint:
	@which golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

# ── tests ──────────────────────────────────────────────────────────────────────
test:
	go test $(GOFLAGS) ./... -timeout 60s

test-unit:
	go test $(GOFLAGS) ./pkg/... -timeout 60s

test-golden:
	go test $(GOFLAGS) ./pkg/schema/... ./pkg/eventlog/... -run TestGolden -v

integration:
	go test $(GOFLAGS) ./integration/... -timeout 120s

conformance:
	cd conformance && python -m pytest -x --timeout=300 -q

# ── build ──────────────────────────────────────────────────────────────────────
build:
	go build -o $(BINARY_AEGISD) ./cmd/aegisd
	go build -o $(BINARY_AEGISCTL) ./cmd/aegisctl

docker:
	docker build -t aegis/aegisd:dev -f build/aegisd.Dockerfile .

docker-dev:
	docker compose -f deploy/docker-compose.dev.yml up --build

docker-prod:
	docker compose -f deploy/docker-compose.prod.yml up -d

docker-down:
	docker compose -f deploy/docker-compose.dev.yml down 2>/dev/null || true
	docker compose -f deploy/docker-compose.prod.yml down 2>/dev/null || true

# ── python sdk ────────────────────────────────────────────────────────────────
python-install:
	cd python && pip install -e ".[dev]"

python-test:
	cd python && python -m pytest -x -q

python-lint:
	cd python && ruff check aegis_sdk/

# ── clean ─────────────────────────────────────────────────────────────────────
clean:
	rm -rf bin/
	find . -name "*.pb.go" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +
