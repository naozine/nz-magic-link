# -----------------------------------------------------------------------------
# Code Quality Targets
# -----------------------------------------------------------------------------
.PHONY: fmt vet lint test vuln check

# Format code
fmt:
	@echo ">> Formatting..."
	gofmt -w .

# Run go vet
vet:
	@echo ">> Running go vet..."
	go vet ./...

# Run golangci-lint
# 要: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
lint:
	@echo ">> Running golangci-lint..."
	golangci-lint run ./...

# Run tests
test:
	@echo ">> Running tests..."
	go test ./...

# Check known vulnerabilities (要ネットワーク)
vuln:
	@echo ">> Running govulncheck..."
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Run all quality checks (lint は要 golangci-lint インストール)
check: fmt vet lint test
