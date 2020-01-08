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

const (
	updateTimeout = 5 * time.Second
)

// makeX509SVIDResponse is a convenience function for generating X509 responses
func setX509SVIDResponse(api *spiffetest.WorkloadAPI, ca *spiffetest.CA, svid []*x509.Certificate, key crypto.Signer) {
	response := &spiffetest.X509SVIDResponse{
		Bundle: ca.Roots(),
		SVIDs: []spiffetest.X509SVID{
			{
				CertChain: svid,
				Key:       key,
			},
		},
	}
	api.SetX509SVIDResponse(response)
}

func TestInitalLoad(t *testing.T) {
	appFS = afero.NewMemMapFs()

	afero.WriteFile(appFS, "certs/example.org.pem", []byte(leafCert), 600)

	workloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer workloadAPI.Stop()

	source, err := NewSpireTrustSource(map[string]string{
		"spiffe://example.org": workloadAPI.Addr(),
	}, "certs/")
	require.NoError(t, err)
	defer source.Stop()

	source.waitForUpdate(t)

	certs := source.TrustedCertificates()["spiffe://example.org"]
	require.Len(t, certs, 1)
	assert.Equal(t, "US", certs[0].Subject.Country[0])
	assert.Equal(t, "test1.acme.com", certs[0].Subject.Organization[0])
	assert.Equal(t, "blog", certs[0].Subject.CommonName)
}

func TestInvalidURI(t *testing.T) {
	_, err := NewSpireTrustSource(map[string]string{
		"spirffe://example.org": "",
	}, "certs/")
	require.Error(t, err)
}

func TestInvalidDomain(t *testing.T) {
	_, err := NewSpireTrustSource(map[string]string{
		"spiffe://example.org/test": "",
	}, "certs/")
	require.Error(t, err)
}

func TestWriteCerts(t *testing.T) {
	appFS = afero.NewMemMapFs()

	workloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer workloadAPI.Stop()

	ca := spiffetest.NewCA(t)
	svidFoo, keyFoo := ca.CreateX509SVID("spiffe://example.org/foo")

	setX509SVIDResponse(workloadAPI, ca, svidFoo, keyFoo)

	source, err := NewSpireTrustSource(map[string]string{
		"spiffe://example.org": workloadAPI.Addr(),
	}, "certs/")
	require.NoError(t, err)

	source.waitForUpdate(t)
	source.Stop()

	dummyWorkloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer dummyWorkloadAPI.Stop()

	newSource, err := NewSpireTrustSource(map[string]string{
		"spiffe://example.org": dummyWorkloadAPI.Addr(),
	}, "certs/")
	newSource.waitForUpdate(t)
	assert.Equal(t, ca.Roots(), newSource.TrustedCertificates()["spiffe://example.org"])
}

func TestSpireOverwrite(t *testing.T) {
	appFS = afero.NewMemMapFs()

	afero.WriteFile(appFS, "certs/example.org.pem", []byte(leafCert), 600)

	workloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer workloadAPI.Stop()

	ca := spiffetest.NewCA(t)
	svidFoo, keyFoo := ca.CreateX509SVID("spiffe://example.org/foo")

	setX509SVIDResponse(workloadAPI, ca, svidFoo, keyFoo)

	source, err := NewSpireTrustSource(map[string]string{
		"spiffe://example.org": workloadAPI.Addr(),
	}, "certs/")
	require.NoError(t, err)
	defer source.Stop()

	source.waitForUpdate(t)
	assert.Equal(t, ca.Roots(), source.TrustedCertificates()["spiffe://example.org"])
}

func TestSpireReload(t *testing.T) {
	appFS = afero.NewMemMapFs()

	workloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer workloadAPI.Stop()

	ca := spiffetest.NewCA(t)
	svidFoo, keyFoo := ca.CreateX509SVID("spiffe://example.org/foo")
	setX509SVIDResponse(workloadAPI, ca, svidFoo, keyFoo)

	source, err := NewSpireTrustSource(map[string]string{
		"spiffe://example.org": workloadAPI.Addr(),
	}, "")
	require.NoError(t, err)
	defer source.Stop()

	source.waitForUpdate(t)
	assert.Equal(t, ca.Roots(), source.TrustedCertificates()["spiffe://example.org"])

	caRot := spiffetest.NewCA(t)
	svidFooRot, keyFooRot := ca.CreateX509SVID("spiffe://example.org/foo")
	setX509SVIDResponse(workloadAPI, caRot, svidFooRot, keyFooRot)

	source.waitForUpdate(t)
	assert.Equal(t, caRot.Roots(), source.TrustedCertificates()["spiffe://example.org"])
}

func (s *SpireTrustSource) waitForUpdate(t *testing.T) {
	select {
	case <-s.updateChan:
	case <-time.After(updateTimeout):
		require.Fail(t, "Timeout exceeding waiting for updates.")
	}
}
