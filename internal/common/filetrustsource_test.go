package common

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSingleCertificate(t *testing.T) {
	appFS = afero.NewMemMapFs()

	afero.WriteFile(appFS, "leaf.pem", []byte(leafCert), 600)

	source, err := NewFileTrustSource(map[string][]string{
		"spiffe://example.org": []string{"leaf.pem"},
	})
	require.NoError(t, err)

	exampleDomain := source.TrustedCertificates()["spiffe://example.org"]
	require.Len(t, exampleDomain, 1)

	assert.Equal(t, "US", exampleDomain[0].Subject.Country[0])
	assert.Equal(t, "test1.acme.com", exampleDomain[0].Subject.Organization[0])
	assert.Equal(t, "blog", exampleDomain[0].Subject.CommonName)
}

func TestDoubleCertificate(t *testing.T) {
	appFS = afero.NewMemMapFs()

	afero.WriteFile(appFS, "chain.pem", []byte(certChain), 600)

	source, err := NewFileTrustSource(map[string][]string{
		"spiffe://example.org": []string{"chain.pem"},
	})
	require.NoError(t, err)

	exampleDomain := source.TrustedCertificates()["spiffe://example.org"]
	require.Len(t, exampleDomain, 2)

	assert := assert.New(t)

	assert.Equal("US", exampleDomain[0].Subject.Country[0])
	assert.Equal("test1.acme.com", exampleDomain[0].Subject.Organization[0])
	assert.Equal("IntermediaetCA", exampleDomain[0].Subject.CommonName)

	assert.Equal("US", exampleDomain[1].Subject.Country[0])
	assert.Equal("test1.acme.com", exampleDomain[1].Subject.Organization[0])
	assert.Equal("blog", exampleDomain[1].Subject.CommonName)
}

func TestBadFile(t *testing.T) {
	appFS = afero.NewMemMapFs()

	_, err := NewFileTrustSource(map[string][]string{
		"spiffe://example.org": []string{"chain.pem"},
	})
	require.Error(t, err)
}

func TestEmptyCerts(t *testing.T) {
	appFS = afero.NewMemMapFs()

	afero.WriteFile(appFS, "chain.pem", []byte(""), 600)

	source, err := NewFileTrustSource(map[string][]string{
		"spiffe://example.org": []string{"chain.pem"},
	})
	require.NoError(t, err)

	exampleDomain := source.TrustedCertificates()["spiffe://example.org"]
	require.Len(t, exampleDomain, 0)
}
