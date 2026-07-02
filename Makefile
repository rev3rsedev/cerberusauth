.PHONY: build test vet run migrate genkey up down clean

BINARY := bin/cerberusd

build:
	go build -trimpath -o $(BINARY) ./cmd/cerberusd

test:
	go test ./...

vet:
	go vet ./...

run:
	go run ./cmd/cerberusd serve

migrate:
	go run ./cmd/cerberusd migrate

# Print a fresh master key (CERBERUS_MASTER_KEY).
genkey:
	go run ./cmd/cerberusd genkey

up:
	docker compose up --build -d

down:
	docker compose down

clean:
	rm -rf bin coverage.out
