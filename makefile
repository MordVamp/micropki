.PHONY: all build test clean

BINARY=micropki
MAIN=cmd/micropki/main.go

all: build

build:
	go build -o $(BINARY) $(MAIN)

test:
	go test -v ./...

clean:
	rm -f $(BINARY)
	go clean