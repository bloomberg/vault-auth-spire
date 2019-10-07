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