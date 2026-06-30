# mdnsscan Makefile
# ---------------------------------------------------------------------------
# 用法:
#   make build         # 在当前 OS 编译到 bin/
#   make build-linux   # 交叉编译到 linux/amd64
#   make test          # go test ./...
#   make test-race     # go test -race ./...
#   make tidy          # go mod tidy
# ---------------------------------------------------------------------------

BIN_DIR      := bin
BIN_NAME     := mdnsscan
LINUX_BIN    := $(BIN_DIR)/$(BIN_NAME)-linux-amd64
PKG          := ./cmd/$(BIN_NAME)

GO           ?= go

.PHONY: all build build-linux test test-race tidy clean

all: build

build:
	$(GO) build -o $(BIN_DIR)/$(BIN_NAME) $(PKG)

build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o $(LINUX_BIN) $(PKG)

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN_DIR)
