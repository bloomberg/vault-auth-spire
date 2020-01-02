package common

import (
	"crypto"
	"crypto/x509"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitalLoad(t *testing.T) {
	appFS = afero.NewMemMapFs()

	certJSON := `{
"certs": {
	"spiffe://example.org": ["MIIB4TCCAUoCCQCfmw3vMgPS5TANBgkqhkiG9w0BAQQFADA1MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wHhcNMTUxMjAzMTkyOTMyWhcNMjkwODEyMTkyOTMyWjA1MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANrq2nhLQj5mlXbpVX3QUPhfEm/vdEqPkoWtR/jRZIWm4WGfWpq/LKHJx2Pqwn+t117syN8l4U5unyAi1BJSXjBwPZNd7dXjcuJ+bRLV7FZ/iuvscfYyQQFTxan4TaJMd0x1HoNDbNbjHa02IyjjYE/r3mb/PIg+J2t5AZEh80lPAgMBAAEwDQYJKoZIhvcNAQEEBQADgYEAjGzp3K3ey/YfKHohf33yHHWd695HQxDAP+wYcs9/TAyLR+gJzJP7d18EcDDLJWVi7bhfa4EAD86di05azOh9kWSn4b3o9QYRGCSwGNnI3Zk0cwNKA49hZntKKiy22DhRk7JAHF01d6Bu3KkHkmENrtJ+zj/+159WAnUaqViorq4="]
}
}`
	afero.WriteFile(appFS, "vault-spire-certs.json", []byte(certJSON), 600)

	workloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer workloadAPI.Stop()

	source, err := NewSpireTrustSource(map[string]string{}, "vault-spire-certs.json")
	require.NoError(t, err)
	certs := source.TrustedCertificates()["spiffe://example.org"]
	require.Len(t, certs, 1)
	assert.Equal(t, x509.MD5WithRSA, certs[0].SignatureAlgorithm)
}

func TestWriteCerts(t *testing.T) {
	appFS = afero.NewMemMapFs()

	workloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer workloadAPI.Stop()

	ca := spiffetest.NewCA(t)
	svidFoo, keyFoo := ca.CreateX509SVID("spiffe://example.org/foo")

	makeX509SVIDResponse := func(svid []*x509.Certificate, key crypto.Signer) *spiffetest.X509SVIDResponse {
		return &spiffetest.X509SVIDResponse{
			Bundle: ca.Roots(),
			SVIDs: []spiffetest.X509SVID{
				{
					CertChain: svid,
					Key:       key,
				},
			},
		}
	}
	workloadAPI.SetX509SVIDResponse(makeX509SVIDResponse(svidFoo, keyFoo))

	source, err := NewSpireTrustSource(map[string]string{
		"spiffe://example.org": workloadAPI.Addr(),
	}, "vault-spire-certs.json")
	require.NoError(t, err)

	time.Sleep(1 * time.Second) // wait for watcher to get new certs
	source.Stop()

	newSource, err := NewSpireTrustSource(map[string]string{}, "vault-spire-certs.json")
	assert.Equal(t, ca.Roots(), newSource.TrustedCertificates()["spiffe://example.org"])
}

func TestSpireOverwrite(t *testing.T) {
	appFS = afero.NewMemMapFs()

	certJSON := `{
"certs": {
	"spiffe://example.org": ["MIIB4TCCAUoCCQCfmw3vMgPS5TANBgkqhkiG9w0BAQQFADA1MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wHhcNMTUxMjAzMTkyOTMyWhcNMjkwODEyMTkyOTMyWjA1MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANrq2nhLQj5mlXbpVX3QUPhfEm/vdEqPkoWtR/jRZIWm4WGfWpq/LKHJx2Pqwn+t117syN8l4U5unyAi1BJSXjBwPZNd7dXjcuJ+bRLV7FZ/iuvscfYyQQFTxan4TaJMd0x1HoNDbNbjHa02IyjjYE/r3mb/PIg+J2t5AZEh80lPAgMBAAEwDQYJKoZIhvcNAQEEBQADgYEAjGzp3K3ey/YfKHohf33yHHWd695HQxDAP+wYcs9/TAyLR+gJzJP7d18EcDDLJWVi7bhfa4EAD86di05azOh9kWSn4b3o9QYRGCSwGNnI3Zk0cwNKA49hZntKKiy22DhRk7JAHF01d6Bu3KkHkmENrtJ+zj/+159WAnUaqViorq4="]
}
}`
	afero.WriteFile(appFS, "vault-spire-certs.json", []byte(certJSON), 600)

	workloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer workloadAPI.Stop()

	ca := spiffetest.NewCA(t)
	svidFoo, keyFoo := ca.CreateX509SVID("spiffe://example.org/foo")

	makeX509SVIDResponse := func(svid []*x509.Certificate, key crypto.Signer) *spiffetest.X509SVIDResponse {
		return &spiffetest.X509SVIDResponse{
			Bundle: ca.Roots(),
			SVIDs: []spiffetest.X509SVID{
				{
					CertChain: svid,
					Key:       key,
				},
			},
		}
	}
	workloadAPI.SetX509SVIDResponse(makeX509SVIDResponse(svidFoo, keyFoo))

	source, err := NewSpireTrustSource(map[string]string{
		"spiffe://example.org": workloadAPI.Addr(),
	}, "vault-spire-certs.json")
	require.NoError(t, err)

	time.Sleep(1 * time.Second) // wait for watcher to get new certs
	assert.Equal(t, ca.Roots(), source.TrustedCertificates()["spiffe://example.org"])
}

func TestSpireReload(t *testing.T) {
	appFS = afero.NewMemMapFs()

	workloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer workloadAPI.Stop()

	ca := spiffetest.NewCA(t)
	svidFoo, keyFoo := ca.CreateX509SVID("spiffe://example.org/foo")

	makeX509SVIDResponse := func(svid []*x509.Certificate, key crypto.Signer) *spiffetest.X509SVIDResponse {
		return &spiffetest.X509SVIDResponse{
			Bundle: ca.Roots(),
			SVIDs: []spiffetest.X509SVID{
				{
					CertChain: svid,
					Key:       key,
				},
			},
		}
	}
	workloadAPI.SetX509SVIDResponse(makeX509SVIDResponse(svidFoo, keyFoo))

	source, err := NewSpireTrustSource(map[string]string{
		"spiffe://example.org": workloadAPI.Addr(),
	}, "")
	require.NoError(t, err)

	time.Sleep(1 * time.Second) // wait for watcher to get new certs
	assert.Equal(t, ca.Roots(), source.TrustedCertificates()["spiffe://example.org"])

	caRot := spiffetest.NewCA(t)
	svidFooRot, keyFooRot := ca.CreateX509SVID("spiffe://example.org/foo")

	makeX509SVIDResponseRot := func(svid []*x509.Certificate, key crypto.Signer) *spiffetest.X509SVIDResponse {
		return &spiffetest.X509SVIDResponse{
			Bundle: caRot.Roots(),
			SVIDs: []spiffetest.X509SVID{
				{
					CertChain: svid,
					Key:       key,
				},
			},
		}
	}
	workloadAPI.SetX509SVIDResponse(makeX509SVIDResponseRot(svidFooRot, keyFooRot))

	time.Sleep(1 * time.Second) // wait for watcher to get new certs
	assert.Equal(t, caRot.Roots(), source.TrustedCertificates()["spiffe://example.org"])
}
