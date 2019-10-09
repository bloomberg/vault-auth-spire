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

This plugin exists to allow Spire authenticated workloads to authenticate with Vault using their Spire provided SVID, and then interact with Vault as they would if they authenticated with Vault via any other Vault supported authentication mechanism. 

The plugin has two operating modes: connected or disconnected from Spire.

## Operating Modes

### Connected to Spire

_Not yet implemented_

When configured to run in connected mode the plugin will use `workload.X509SVIDClient` to receive from Spire (via the agent) the various trust bundles to verify SVIDs against. The plugin will be notified, in relative real-time, of any changes to trust bundles.

### Disconnected from Spire

When configured to run in disconnected mode the plugin needs to be provided with all the trust domains and their associated CAs. These will then be used to verify SVIDs against.

To run in this mode the following block should exist in the plugin's setting file.

```json
{
  ...other settings...,

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

In order to support certificate rotation each domain can be validated against multiple CA files. Also, each CA file can themselves contain multiple CA blocks. This allows users to choose what is easiest for them - a distinct files for each CA or a single file with all CAs. All will be read and used to verify SVIDs.

## Quick Start

## Building

## Installation

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

---

# Saving for posterity - to be updated soon

# vault-auth-spire

#### This is a work in progress and no where near ready

Provides a [Vault Auth Plugin](https://www.vaultproject.io/docs/internals/plugins.html) supporting the use of Spiffe SVIDs for authentication.

### To Build

$> make




#### Does SVID Validation against Spire

Saving for posterity

```go
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	//"github.com/spiffe/go-spiffe/spiffe"

	//"github.com/spiffe/go-spiffe/workload"
	"strings"

	// "context"
	// "crypto/subtle"
	// "errors"
	"log"
	"os"
	// "time"

	"github.com/hashicorp/vault/api"
	// "github.com/hashicorp/vault/sdk/framework"
	// "github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	standardVaultPluginInit()
}

var pluginSettingsFilePath string

func standardVaultPluginInit(){
	// This is all standard Vault auth plugin initialization stuff
	apiClientMeta := &api.PluginAPIClientMeta{}
	apiStandardFlags := apiClientMeta.FlagSet()
	apiStandardFlags.Parse(os.Args[1:])


	settingsFlags := flag.NewFlagSet("vault-auth-spire flags", flag.ContinueOnError)
	settingsFlags.StringVar(&pluginSettingsFilePath, "settings-file", "", "Path to plugin settings")
	settingsFlags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: BackendFactory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}

func BackendFactory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {

	b := Backend(c)

	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
	//svidWatcher *testWatcher
	//svidClient *workload.X509SVIDClient

	logger *log.Logger
}

func Backend(c *logical.BackendConfig) *backend {
	var b backend

	f, err := os.OpenFile("/tmp/vault-auth-spire.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}

	b.logger = log.New(f, "vault-auth-spire: ", log.LstdFlags)
	b.logger.Println("Logger has started")

	b.logger.Println("The settings file path is " + pluginSettingsFilePath)

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
		},
		Paths: []*framework.Path{
			&framework.Path{
				Pattern: "login",
				Fields: map[string]*framework.FieldSchema{
					"svid": &framework.FieldSchema{
						Type: framework.TypeString,
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback:    b.pathAuthLogin,
						Summary:     "Login via Spiffe/Spire SVID",
					},
				},
			},
		},
	}

	//b.svidWatcher = newTestWatcher()
	//b.svidClient, _ = workload.NewX509SVIDClient(b.svidWatcher, workload.WithAddr("unix:///tmp/agent.sock"))
	//b.svidClient.Start()
	//
	//b.logger.Println("Plugin has been configured and svidClient started")

	return &b
}

func (b *backend) pathAuthLogin(_ context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	svid := d.Get("svid").(string)

	if len(svid) <= 0 {
		return nil, logical.ErrPermissionDenied
	}

	b.logger.Println("I got svid " + svid)

	block, _ := pem.Decode([]byte(svid))
	if block == nil {
		b.logger.Println("failed to parse certificate PEM")
	}
	svidCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		b.logger.Println("failed to parse certificate: " + err.Error())
	}
	b.logger.Println("I created a valid x509.Certificate out of the pem")

	//var trustCertPool = x509.NewCertPool()
	//for _,cert := range b.svidWatcher.TrustBundle{
	//	trustCertPool.AddCert(cert)
	//}
	//b.logger.Println("I created certPool")

	//var certPoolMap = make(map[string]*x509.CertPool)
	//certPoolMap["spiffe://dev.bloomberg.com"] = trustCertPool
	//b.logger.Println("I created certPoolMap")

	//_, err = spiffe.VerifyPeerCertificate([]*x509.Certificate{svidCert}, certPoolMap, spiffe.ExpectAnyPeer())
	//b.logger.Println("I called VerifyPeerCertificate")

	uris := []string{}
	for _, uri := range svidCert.URIs{
		b.logger.Println("Found URI: " + uri.String())
		uris = append(uris, uri.String())
	}

	var result string
	ifnil != err{
		b.logger.Println("There was an error: " + err.Error())
		result = "There was an error: " + err.Error()
	} else{
		b.logger.Println("The cert was verified")
		result = "We've been verified and I found URIs: " + strings.Join(uris, ",")
	}

	// Compose the response
	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"receivedSvid": svid,
			},
			Policies: []string{
				//"Trust Bundles: " + strconv.Itoa(len(b.svidWatcher.TrustBundle)),
				"Result: " + result,
			},
			Metadata: map[string]string{
				"spiffeId": uris[0],
			},
			LeaseOptions: logical.LeaseOptions{
				Renewable: false,
			},
		},
	}, nil
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// TODO
	return nil, nil
}

//type testWatcher struct {
//	TrustBundle  []*x509.Certificate
//	Errors       []error
//}
//
//func newTestWatcher() *testWatcher {
//	return &testWatcher{
//		//updateSignal: make(chan struct{}, 100),
//		//timeout:      10 * time.Second,
//	}
//}
//
//func (w *testWatcher) UpdateX509SVIDs(u *workload.X509SVIDs) {
//	if len(u.SVIDs) > 0 {
//		w.TrustBundle = u.SVIDs[0].TrustBundle
//	}
//}
//
//func (w *testWatcher) OnError(err error) {
//	w.Errors = append(w.Errors, err)
//}
```