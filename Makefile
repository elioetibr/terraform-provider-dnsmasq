HOSTNAME=registry.terraform.io
NAMESPACE=elioseverojunior
NAME=dnsmasq
BINARY=terraform-provider-${NAME}
VERSION=0.1.0
OS_ARCH=$(shell go env GOOS)_$(shell go env GOARCH)

# Fix for Go toolchain mismatch - set GOROOT to match go binary version
GO_VERSION=$(shell go version | sed -E 's/go version go([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
GOROOT_FIX=$(shell [ -d "/usr/local/Cellar/go/$(GO_VERSION)/libexec" ] && echo "GOROOT=/usr/local/Cellar/go/$(GO_VERSION)/libexec" || echo "")

.PHONY: build install test testacc fmt vet clean tidy docs lint all

default: build

build:
	$(GOROOT_FIX) go build -o ${BINARY}

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	cp ${BINARY} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}/

test:
	$(GOROOT_FIX) go test ./... -v -timeout 120s

testacc:
	$(GOROOT_FIX) TF_ACC=1 go test ./... -v -timeout 120m

fmt:
	$(GOROOT_FIX) go fmt ./...

vet:
	$(GOROOT_FIX) go vet ./...

clean:
	rm -f ${BINARY}

tidy:
	$(GOROOT_FIX) go mod tidy

docs:
	$(GOROOT_FIX) tfplugindocs generate --provider-name ${NAME}

lint:
	$(GOROOT_FIX) golangci-lint run ./...

all: fmt vet build test docs
