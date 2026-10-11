.PHONY: check-kit tidy test vet race sync-web fonts i18n-check runtime-check build build-all clean smoke

# The unpublished kit module is consumed as the sibling checkout ../kit.
check-kit:
	@test -f ../kit/go.mod || { echo "MeshBridge requires the sibling MineAI kit checkout at ../kit (kit/go.mod missing)." >&2; exit 1; }

tidy: check-kit
	go mod tidy

test: sync-web
	go test ./... -count=1

vet: check-kit
	go vet ./...

race: check-kit
	go test -race ./... -count=1

# The server binary embeds the UI; web/ is canonical, the embed copy is generated.
sync-web: check-kit
	rm -rf cmd/meshbridge-server/web
	mkdir -p cmd/meshbridge-server/web
	cp -R web/. cmd/meshbridge-server/web/

# Re-subset CJK display fonts after editing titles in web/assets/i18n (needs network).
fonts:
	python3 scripts/fetch-fonts.py

i18n-check: check-kit
	python3 scripts/check-i18n.py

runtime-check: check-kit
	node --check web/assets/app.js
	node --check web/assets/rules.js
	node --check ../kit/web/assets/kit/cache.js
	node --check ../kit/web/assets/kit/chrome.js
	node --check ../kit/web/assets/kit/sso.js
	node ../kit/web/runtime_test.cjs
	node ../kit/web/sso_runtime_test.cjs
	node ../kit/web/cache_runtime_test.cjs
	node scripts/cache_test.cjs
	node scripts/rules_test.cjs

build: sync-web
	go build -o bin/meshbridge-server ./cmd/meshbridge-server
	go build -o bin/meshbridge-agent ./cmd/meshbridge-agent
	go build -o bin/meshbridge-cli ./cmd/meshbridge-cli

build-all: sync-web
	GOOS=linux GOARCH=amd64 go build -o dist/meshbridge-server-linux-amd64 ./cmd/meshbridge-server
	GOOS=linux GOARCH=amd64 go build -o dist/meshbridge-agent-linux-amd64 ./cmd/meshbridge-agent
	GOOS=windows GOARCH=amd64 go build -o dist/meshbridge-agent-windows-amd64.exe ./cmd/meshbridge-agent
	GOOS=darwin GOARCH=arm64 go build -o dist/meshbridge-agent-darwin-arm64 ./cmd/meshbridge-agent
	GOOS=darwin GOARCH=amd64 go build -o dist/meshbridge-agent-darwin-amd64 ./cmd/meshbridge-agent

clean:
	rm -rf bin dist

smoke:
	bash scripts/smoke-test.sh
