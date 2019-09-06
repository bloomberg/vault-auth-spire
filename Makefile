
all: build

build: clean build/docker/* *.go
	@GOOS=linux go build

deploy: build
	@cp vault-auth-spire ../subrosa-local-dev/setup/vault/plugins/vault-auth-spire
	@echo "Built and copied vault-auth-spire to ../subrosa-local-dev/setup/vault/plugins/vault-auth-spire"

clean:
	@rm -f vault-auth-spire