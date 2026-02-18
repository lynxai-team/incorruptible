help:
	# make all    Upgrade, Generate, Format, Go test/lint
	# make up     Upgrade the patch version of the dependencies
	# make up+    Upgrade the minor version of the dependencies
	# make fmt    Generate code and Format code
	# make test   Check build and Test
	# make cov    Browse test coverage
	# make fix    Run example and Lint

.PHONY: all
all: up fmt test fix

go.mod:
	go mod init github.com/lynxai-team/incorruptible
	go mod tidy

go.sum: go.mod
	go mod tidy

.PHONY: up
up: go.sum
	GOPROXY=direct go get -t -u=patch all
	go mod tidy

.PHONY: up+
up+: go.sum
	go get -u -t all
	go mod tidy

.PHONY: fmt
fmt:
	go generate ./...
	go run mvdan.cc/gofumpt@latest -w -extra -l .

.PHONY: test
test: code-coverage.out
	go build ./...

.PHONY: cov
cov: code-coverage.out
	go tool cover -html code-coverage.out

code-coverage.out: go.sum *.go Makefile
	go test -vet all -tags=emo -coverprofile=code-coverage.out ./...

.PHONY: fix
fix:
	go fix ./...
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run --fix
