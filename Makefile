all: build

build: clean cmd/plugin/vault-auth-spire.go
	GOOS=linux GOARCH=amd64 go build -o vault-auth-spire cmd/plugin/vault-auth-spire.go

deploy: build
	@cp vault-auth-spire vault-auth-spire-settings.json ../subrosa-local-dev/setup/vault/plugins/
	@echo "Built and copied vault-auth-spire to ../subrosa-local-dev/setup/vault/plugins/vault-auth-spire"

clean:
	@rm -f vault-auth-spire
