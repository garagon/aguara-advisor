.PHONY: build test lint install clean

build:
	go build -o aguara-mcp .

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

install:
	go install .

clean:
	rm -f aguara-mcp
