package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"go.dev.bloomberg.com/bbgo/go-logrus"
	"strings"

	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	standardVaultPluginInit()
}

func standardVaultPluginInit() {

	// This is all standard Vault auth plugin initialization stuff

	// Standard args that are passed into every plugin
	apiClientMeta := &api.PluginAPIClientMeta{}
	apiStandardFlags := apiClientMeta.FlagSet()
	apiStandardFlags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: BackendFactory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}

func BackendFactory(ctx context.Context, backendConfig *logical.BackendConfig) (logical.Backend, error) {

	settings, err := parseSettings()
	if nil != err {
		return nil, err
	}

	if err := initializeLogger(settings); err != nil {
		return nil, errors.New("vault-auth-spire: Failed to initialize logging - " + err.Error())
	}

	var spirePlugin spirePlugin
	spirePlugin.settings = settings
	spirePlugin.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   spirePlugin.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
		},
		Paths: []*framework.Path{
			{
				Pattern: "login",
				Fields: map[string]*framework.FieldSchema{
					"svid": {
						Type: framework.TypeString,
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: spirePlugin.pathAuthLogin,
						Summary:  "Login via Spiffe/Spire SVID",
					},
				},
			},
		},
	}

	if err := spirePlugin.Setup(ctx, backendConfig); err != nil {
		return nil, errors.New("vault-auth-spire: Failed in call to spirePlugin.Setup(ctx, backendConfig) - " + err.Error())
	}
	return spirePlugin, nil
}

func parseSettings() (*Settings, error) {
	var settingsFilePath string

	// Arguments specific to vault-auth-plugin
	settingsFlags := flag.NewFlagSet("vault-auth-spire flags", flag.ContinueOnError)
	settingsFlags.StringVar(&settingsFilePath, "settings-file", "", "Path to plugin settings")
	settingsFlags.Parse(os.Args[1:])

	if settings, err := ReadSettings(settingsFilePath); err != nil {
		return nil, errors.New("vault-auth-spire: Failed to read settings from '" + settingsFilePath + "' - " + err.Error())
	} else {
		return settings, nil
	}
}

type spirePlugin struct {
	settings *Settings
	*framework.Backend
}

func (spirePlugin *spirePlugin) pathAuthLogin(_ context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	svid := d.Get("svid").(string)

	if len(svid) <= 0 {
		return nil, logical.ErrPermissionDenied
	}

	logrus.Info("I got svid " + svid)
	//b.logger.Println("FilePath1: " + b.settings.settingsFilePath)

	block, _ := pem.Decode([]byte(svid))
	if block == nil {
		logrus.Info("failed to parse certificate PEM")
	}
	svidCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logrus.Info("failed to parse certificate: " + err.Error())
	}
	logrus.Info("I created a valid x509.Certificate out of the pem")

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
	for _, uri := range svidCert.URIs {
		logrus.Info("Found URI: " + uri.String())
		uris = append(uris, uri.String())
	}

	var result string
	if nil != err {
		logrus.Info("There was an error: " + err.Error())
		result = "There was an error: " + err.Error()
	} else {
		logrus.Info("The cert was verified")
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

func (spirePlugin *spirePlugin) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// TODO
	return nil, nil
}
