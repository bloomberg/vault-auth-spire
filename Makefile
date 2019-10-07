
all: build

build: clean build/docker/* *.go
	@GOOS=linux go build

deploy: build
	@cp vault-auth-spire vault-auth-spire-settings.json ../subrosa-local-dev/setup/vault/plugins/
	@echo "Built and copied vault-auth-spire to ../subrosa-local-dev/setup/vault/plugins/vault-auth-spire"

clean:
	@rm -f vault-auth-spire