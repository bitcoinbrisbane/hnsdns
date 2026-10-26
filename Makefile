VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 linux/arm windows/amd64

.PHONY: build test vet cross docker run clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/hnsdns ./cmd/hnsdns

test:
	go test -race -count=1 ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

cross:
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  echo "building $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
	    -o dist/hnsdns-$$os-$$arch$$ext ./cmd/hnsdns || exit 1; \
	done

docker:
	docker build --build-arg VERSION=$(VERSION) -t hnsdns:$(VERSION) .

# Needs hnsd running with its root server on 127.0.0.1:5369.
run: build
	sudo ./bin/hnsdns -v

clean:
	rm -rf bin dist
