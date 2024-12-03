.PHONY: build test lint clean

build:
	go build -v ./...

test:
	go test -v -race -cover ./...

lint:
	golangci-lint run

clean:
	go clean
	rm -f traefik-cas-auth