package common

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/spf13/afero"
	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func certToFile(cert *x509.Certificate, fileName string) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	afero.WriteFile(appFS, fileName, pem.EncodeToMemory(block), 600)
}

func TestValid(t *testing.T) {
	appFS = afero.NewMemMapFs()

	ca := spiffetest.NewCA(t)
	certToFile(ca.Roots()[0], "ca.pem")
	svidFoo, _ := ca.CreateX509SVID("spiffe://example.org/foo")

	source, err := NewFileTrustSource(map[string][]string{
		"spiffe://example.org": []string{"ca.pem"},
	})
	require.NoError(t, err)

	verif := NewSvidVerifier()
	verif.AddTrustSource(source)

	svidBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: svidFoo[0].Raw,
	}

	id, err := verif.VerifyAndExtractSpiffeId(string(pem.EncodeToMemory(svidBlock)))
	assert.Equal(t, "spiffe://example.org/foo", id)
}

func TestDifferentDomain(t *testing.T) {
	appFS = afero.NewMemMapFs()

	ca := spiffetest.NewCA(t)
	certToFile(ca.Roots()[0], "ca.pem")
	svidFoo, _ := ca.CreateX509SVID("spiffe://wrong.org/foo")

	source, err := NewFileTrustSource(map[string][]string{
		"spiffe://example.org": []string{"ca.pem"},
	})
	require.NoError(t, err)

	verif := NewSvidVerifier()
	verif.AddTrustSource(source)

	svidBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: svidFoo[0].Raw,
	}

	_, err = verif.VerifyAndExtractSpiffeId(string(pem.EncodeToMemory(svidBlock)))
	assert.Error(t, err)
}

func TestBadCA(t *testing.T) {
	appFS = afero.NewMemMapFs()

	ca := spiffetest.NewCA(t)
	certToFile(ca.Roots()[0], "ca.pem")
	ca2 := spiffetest.NewCA(t)
	svidFoo, _ := ca2.CreateX509SVID("spiffe://example.org/foo")

	source, err := NewFileTrustSource(map[string][]string{
		"spiffe://example.org": []string{"ca.pem"},
	})
	require.NoError(t, err)

	verif := NewSvidVerifier()
	verif.AddTrustSource(source)

	svidBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: svidFoo[0].Raw,
	}

	_, err = verif.VerifyAndExtractSpiffeId(string(pem.EncodeToMemory(svidBlock)))
	assert.Error(t, err)
}
