GO_CACHE_DIR ?= /tmp/wheredns-go-cache
GO_FLAGS := -buildvcs=false

.PHONY: build test check release run clean

build:
	mkdir -p bin
	GOCACHE=$(GO_CACHE_DIR) go build $(GO_FLAGS) -o bin/wheredns ./cmd/wheredns

test:
	GOCACHE=$(GO_CACHE_DIR) go test ./...

check:
	GOCACHE=$(GO_CACHE_DIR) go test -race ./...
	GOCACHE=$(GO_CACHE_DIR) go vet ./...

release:
	@test -n "$(VERSION)" || (echo "usage: make release VERSION=v0.1.0" && exit 2)
	GOCACHE=$(GO_CACHE_DIR) scripts/build-release.sh "$(VERSION)"

run: build
	./bin/wheredns serve

clean:
	rm -rf bin
