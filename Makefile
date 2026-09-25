.PHONY: tidy test vet race sync-web fonts i18n-check build build-all clean smoke

tidy:
	go mod tidy

test: sync-web
	go test ./... -count=1

vet:
	go vet ./...

race:
	go test -race ./... -count=1

# The server binary embeds the UI; web/ is canonical, the embed copy is generated.
sync-web:
	rm -rf cmd/meshbridge-server/web
	mkdir -p cmd/meshbridge-server/web
	cp -R web/. cmd/meshbridge-server/web/

# Re-subset CJK display fonts after editing titles in web/assets/i18n (needs network).
fonts:
	python3 scripts/fetch-fonts.py

i18n-check:
	python3 scripts/check-i18n.py

build: sync-web
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
