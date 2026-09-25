.PHONY: tidy test vet build build-all clean smoke

tidy:
	go mod tidy

test:
	go test ./... -count=1

vet:
	go vet ./...

race:
	go test -race ./... -count=1

build:
	go build -o bin/meshbridge-server ./cmd/meshbridge-server
	go build -o bin/meshbridge-agent ./cmd/meshbridge-agent
	go build -o bin/meshbridge-cli ./cmd/meshbridge-cli

build-all:
	GOOS=linux GOARCH=amd64 go build -o dist/meshbridge-server-linux-amd64 ./cmd/meshbridge-server
	GOOS=linux GOARCH=amd64 go build -o dist/meshbridge-agent-linux-amd64 ./cmd/meshbridge-agent
	GOOS=windows GOARCH=amd64 go build -o dist/meshbridge-agent-windows-amd64.exe ./cmd/meshbridge-agent
	GOOS=darwin GOARCH=arm64 go build -o dist/meshbridge-agent-darwin-arm64 ./cmd/meshbridge-agent
	GOOS=darwin GOARCH=amd64 go build -o dist/meshbridge-agent-darwin-amd64 ./cmd/meshbridge-agent

clean:
	rm -rf bin dist

smoke:
	bash scripts/smoke-test.sh
