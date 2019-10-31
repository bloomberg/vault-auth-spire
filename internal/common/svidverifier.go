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

package common

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/spiffe"
)

// SvidVerifier can be used to verify any SVID against a sets of trusted domains. The source of trust
// used to verify the SVIDs against is contained within the `trustSources`, which contains all of the
// sources of trust this SvidVerifier can use to verify against.
type SvidVerifier struct {
	trustSources []TrustSource
}

func NewSvidVerifier() SvidVerifier {
	return SvidVerifier{
		trustSources: make([]TrustSource, 0),
	}
}

// AddTrustSource adds a new source of trust to this SvidVerifier
func (verifier *SvidVerifier) AddTrustSource(source TrustSource) {
	verifier.trustSources = append(verifier.trustSources, source)
}

// VerifyAndExtractSpiffeId will take the provided SVID and verify its source against any of the known
// sources of trust. If the SVID was generated using any of the known sources of trust and adheres to
// all required SPIFFE requirements for an SVID then the SVID will be considered verified and the
// SPIFFE ID of the SVID will be returned. If the SVID cannot be verified then an error will
// be returned.
func (verifier *SvidVerifier) VerifyAndExtractSpiffeId(svid string) (string, error) {
	logrus.Debug("Beginning SVID verification")

	// right now we only support X509 verification
	spiffeId, err := verifier.verifyAndExtractSpiffeIdFromX509(svid)
	if err != nil {
		return "", err
	}

	// SPIFFE validation requirements
	if err := spiffe.ValidateID(spiffeId, spiffe.AllowAnyTrustDomainWorkload()); err != nil {
		return "", errors.New("SVID is invalid - invalid SPIFFE ID found - " + err.Error())
	}

	return spiffeId, nil
}

// VerifyAndExtractSpiffeIdFromX509 will take the provided X509-SVID and verify its source against any
// of the known sources of trust. If the SVID was generated using any of the known sources of trust
// and adheres to all required SPIFFE requirements for an X509-SVID then it will be considered verified
// and the SPIFFE ID found in the SVID will be returned. If the SVID cannot be verified then an error will
// be returned. The SPIFFE ID of an X509-SVID is defined as the first SAN URI found in the first certificate
// of the SVID. That is, if it contains multiple certificates then the first is the one containing the
// 'caller' SPIFFE ID.
func (verifier *SvidVerifier) verifyAndExtractSpiffeIdFromX509(svid string) (string, error) {
	logrus.Debug("Beginning SVID X509 verification")

	logrus.Debug("Extracting certificates from provided SVID")
	svidCertChain := ExtractCertificatesFromPem([]byte(svid))
	if len(svidCertChain) == 0 {
		return "", errors.New("SVID is invalid - no valid certificates found")
	}
	svidPrincipalCert := svidCertChain[0]

	logrus.Debug("Building map of domains -> trusted certificate pools")
	trustedCertificatePools := make(map[string]*x509.CertPool, 0)
	for _, source := range verifier.trustSources {
		for domain, certificates := range source.TrustedCertificates() {
			pool, exists := trustedCertificatePools[domain]
			if !exists {
				pool = x509.NewCertPool()
				trustedCertificatePools[domain] = pool
			}
			for _, certificate := range certificates {
				pool.AddCert(certificate)
			}
		}
	}

	_, err := spiffe.VerifyPeerCertificate(svidCertChain, trustedCertificatePools, spiffe.ExpectAnyPeer())
	if nil != err {
		return "", errors.New("Failed to validate SVID against trust chain - " + err.Error())
	}

	if len(svidPrincipalCert.URIs) == 0 {
		return "", errors.New("SVID is invalid - no SPIFFE ID found")
	}

	return svidPrincipalCert.URIs[0].String(), nil
}

// ExtractCertificatesFromPem takes an array of bytes representing a PEM file
// and extracts any and all certificates located within that PEM data. This logic
// in this method has been borrowed from x509.CertPool::AppendCertsFromPEM which
// accepts the same argument, extracts, and appends the certificates to an
// x509.CertPool.
// The SPIFFE Workload API, reiterating what is declared in the TLS RFC, states
// that the order of the certificates in the PEM file is important and as such
// this method will ensure the order of certificates will be preserved.
// https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Workload_API.md#54-profile-messages
func ExtractCertificatesFromPem(pemCerts []byte) []*x509.Certificate {
	var certificates []*x509.Certificate

	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		certificates = append(certificates, cert)
	}

	return certificates
}
