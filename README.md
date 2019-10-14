# SPIRE Vault Authentication Plugin

SPIRE Vault Authentication Plugin is an authentication plugin for [Hashicorp Vault](https://www.vaultproject.io) which allows logging into Vault using a Spire provided SVID.

## Menu

- [Rationale](#rationale)
- [Quick start](#quick-start)
- [Building](#building)
- [Installation](#installation)
- [Contributions](#contributions)
- [License](#license)
- [Code of Conduct](#code-of-conduct)
- [Security Vulnerability Reporting](#security-vulnerability-reporting)

## Rationale

This plugin exists to allow Spire authenticated workloads to authenticate with Vault using their Spire provided SVID, and then interact with Vault as they would if they authenticated with Vault via any other Vault supported authentication mechanism. The intention is to support the following login scenerio
```
$> vault write auth/spire/login svid="$(cat svid.0.pem)"
```
where `svid.0.pem` contains a valid SVID with some SpiffeID in it and the SpiffeID will be used to determine which policies to apply during the Vault session.

During the login process the provided SVID will be verified against CA trust bundles known to the plugin. The SVID must have been generated using one of the known CA trust bundles. As per the rules in Spiffe regarding [trust domains and bundles](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Trust_Domain_and_Bundle.md), each trust domain known to the plugin will use 1 or more public CAs to verify SVIDs generated in that domain. The `vault-auth-spire` plugin supports the configuration of multiple trust domains, each with 1 or more root or intermediate CAs used to verify the SVIDs. This use of 1 or more CAs allows the plugin to support CA rotation.

The plugin uses Trust Sources to manage from where it receives trusted CAs. There are two types of trust sources: read from file and pushed from spire. The trust sources are configured in the plugin settings and will be used to acquire trust CAs. The plugin can simultaneously acquire trust CAs from file and Spire.

### Trust Sources

A Trust Source provides a way for `vault-auth-spire` to acquire trust CAs. There are two types of trust sources: from file and Spire. Both types of trust sources can be used at the same time.

#### File Trust Source

When using a File Trust Source one needs to map a Trust Domain to one or more files containing the trusted CAs for that domain. This information is provided to the plugin via its settings file.

```json
{
  "trustsource": {
    "file": {
      "domains": {
        "spiffe://some.domain.com": ["/path/to/ca/for/domain.crt", "/path/to/secondary/ca/for/domain.crt"],
        "spiffe://some.otherdomain.com": ["/path/to/ca/for/otherdomain.crt"]
      }
    }
  }
}
```

Each domain can be provided with one or more trusted CA files and each CA file can contain one or more actual certificates. The full set of certificates found across all files will be used to verify SVIDs claiming to be within the configured domain. This structure allows the plugin to fully support certificate rotation.

#### Spire Trust Source

**This is still under development and some details are unknown at this time**

When using the Spire Trust Source one needs to provide enough information for the plugin to connect to Spire and retreive its known trust CAs. The information is provided to the plugin via its settings file

```json
{
  "trustsource": {
    "spire": ...unknown at the moment...
  }
}
```

Current ideas for this trust source include

1. Support connecting to multiple Spire instances (agents or servers) to allow for broad authentication, particularly where different systems are using the same Vault instance.
2. Support saving the Spire provided CAs to disk so they can be used if the plugin is unable to connect to a Spire instance. This will help limit the blast radius of a failing Spire connection.

## Quick Start

## Building

The plugin can be built using standard `go` commands or simply by using the provided [`Makefile`](Makefile).

```
$> make build
GOOS=linux GOARCH=amd64 go build -o vault-auth-spire cmd/plugin/vault-auth-spire.go
```

## Installation

The plugin is installed and registered just like [any other Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html#plugin-registration). It should be placed in the appropriate plugin directory and registered in the catalog. When registering the plugin it is necessary to provide the location of the plugin settings file.

```
$> vault write sys/plugins/catalog/auth/spire \
    sha_256="$(shasum -a 256 '/path/to/plugin/vault-auth-spire' | cut -d' ' -f1)" \
    command="vault-auth-spire" \
    args="--settings-file=/path/to/settings/vault-auth-spire-settings.json"
```

Before usage all plugins need to be enabled

```
$> vault auth enable \
    -path="spire" \
    -plugin-name="spire" plugin
```

## Contributions

We :heart: contributions.

Have you had a good experience with this project? Why not share some love and contribute code, or just let us know about any issues you had with it?

We welcome issue reports [here](../../issues); be sure to choose the proper issue template for your issue, so that we can be sure you're providing the necessary information.

Before sending a [Pull Request](../../pulls), please make sure you read our
[Contribution Guidelines](https://github.com/bloomberg/.github/blob/master/CONTRIBUTING.md).

## License

Please read the [LICENSE](LICENSE) file.

## Code of Conduct

This project has adopted a [Code of Conduct](https://github.com/bloomberg/.github/blob/master/CODE_OF_CONDUCT.md).
If you have any concerns about the Code, or behavior which you have experienced in the project, please
contact us at opensource@bloomberg.net.

## Security Vulnerability Reporting

If you believe you have identified a security vulnerability in this project, please send email to the project
team at opensource@bloomberg.net, detailing the suspected issue and any methods you've found to reproduce it.

Please do NOT open an issue in the GitHub repository, as we'd prefer to keep vulnerability reports private until
we've had an opportunity to review and address them.
