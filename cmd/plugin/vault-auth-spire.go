/*
 ** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package main

import (
	"context"
	"errors"
	"flag"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"go.dev.bloomberg.com/bbgo/go-logrus"
	"strings"
	"vault-auth-spire/internal/common"

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

// BackendFactory creates the plugin backend and configures how login requests are handled. If there is
// a failure in properly setting up the plugin then BackendFactory returns an error detailing what the
// failure is. This error is printed to Vault's standard log, and not the log configured for this
// specific plugin.
//
// The plugin requires a single CLI argument when started (which is provided to Vault when registering
// the plugin and passed to the plugin when started by Vault) called `settings-file` which is the
// absolute path to a valid file containing plugin settings. Inability to find or read this file will
// result in failure of the plugin to start. Details about that settings file requirements are described
// elsewhere in this package.
func BackendFactory(ctx context.Context, backendConfig *logical.BackendConfig) (logical.Backend, error) {

	settings, err := parseSettings()
	if nil != err {
		return nil, err
	}

	if err := common.InitializeLogger(settings); err != nil {
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

	spirePlugin.verifier = common.NewSvidVerifier()

	if nil != settings.SourceOfTrust.File {
		trustSource, err := common.NewTrustFileSource(settings.SourceOfTrust.File.Domains)
		if err != nil {
			return nil, errors.New("vault-auth-spire: Failed to initialize file TrustSource - " + err.Error())
		}
		spirePlugin.verifier.AddTrustSource(&trustSource)
	} else {
		return nil, errors.New("vault-auth-spire: No verifier found in settings")
	}

	// Calls standard Vault plugin setup - magic happens here I bet :shrugs: but if it fails then we're gonna
	// kill the plugin
	if err := spirePlugin.Setup(ctx, backendConfig); err != nil {
		return nil, errors.New("vault-auth-spire: Failed in call to spirePlugin.Setup(ctx, backendConfig) - " + err.Error())
	}

	return spirePlugin, nil
}

// parseSettings uses the expected `settings-file` CLI argument to load a file containing settings for this plugin.
func parseSettings() (*common.Settings, error) {
	var settingsFilePath string

	// Arguments specific to vault-auth-plugin
	settingsFlags := flag.NewFlagSet("vault-auth-spire flags", flag.ContinueOnError)
	settingsFlags.StringVar(&settingsFilePath, "settings-file", "", "Path to plugin settings")
	settingsFlags.Parse(os.Args[1:])

	if settings, err := common.ReadSettings(settingsFilePath); err != nil {
		return nil, errors.New("vault-auth-spire: Failed to read settings from '" + settingsFilePath + "' - " + err.Error())
	} else {
		return settings, nil
	}
}

// spirePlugin is-a framework.Backend as per the embedded unnamed anon field
type spirePlugin struct {
	*framework.Backend
	settings  *common.Settings
	verifier common.SvidVerifier
}

// pathAuthLogin is called when something attempts to login to Vault using this plugin's method (ie, spire). A login request
// requires an SVID argument (of type string) containing a valid SVID that can verified as per the plugin's settings. If the
// SVID is verified then the contained SpiffeId will be used as the identifying piece of information about the user
func (spirePlugin *spirePlugin) pathAuthLogin(_ context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	svid := d.Get("svid").(string)

	if len(svid) <= 0 {
		return nil, logical.ErrInvalidRequest
	}

	svidCerts, err := spirePlugin.verifier.Verify(svid)
	if err != nil {
		logrus.Debug("Provided svid could not be verified - " + err.Error())
		return nil, logical.ErrPermissionDenied
	}

	uris := []string{}
	for _, svidCert := range svidCerts {
		for _, uri := range svidCert.URIs {
			logrus.Info("Found URI: " + uri.String())
			uris = append(uris, uri.String())
		}
	}

	logrus.Info("The cert was verified")

	// Compose the response
	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"receivedSvid": svid,
			},
			Policies: []string{
				//"Trust Bundles: " + strconv.Itoa(len(b.svidWatcher.TrustBundle)),
				"Result: We've been verified and I found URIs: " + strings.Join(uris, ","),
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
