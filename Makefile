all: build

build: clean cmd/plugin/vault-auth-spire.go
	GOOS=linux GOARCH=amd64 go build -o vault-auth-spire cmd/plugin/vault-auth-spire.go

clean:
	@rm -f vault-auth-spire
