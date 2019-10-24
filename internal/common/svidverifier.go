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
	"github.com/spiffe/go-spiffe/spiffe"
	"github.com/sirupsen/logrus"
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

// Verify will take the provided SVID and verify its source against any of the known sources of trust.
// If the SVID was generated using any of the known sources of trust then the SVID will be considered
// verified and all the certificates found inside the SVID will be returned. If the SVID cannot be
// verified then an error will be returned.
func (verifier *SvidVerifier) Verify(svid string) ([]*x509.Certificate, error){

	logrus.Debug("Beginning SVID verification")

	logrus.Debug("Extracting certificates from provided SVID")
	svidCerts := ExtractCertificatesFromPem([]byte(svid))
	if len(svidCerts) == 0 {
		return nil, errors.New("SVID is invalid - no valid certificates found")
	}

	logrus.Debug("Building map of domains -> trusted certificate pools")
	trustedCertificatePools := make(map[string]*x509.CertPool,0)
	for _, source := range verifier.trustSources {
		for domain, certificates := range source.TrustedCertificates(){
			pool, exists := trustedCertificatePools[domain]
			if !exists {
				pool = x509.NewCertPool()
				trustedCertificatePools[domain] = pool
			}
			for _, certificate := range certificates{
				pool.AddCert(certificate)
			}
		}
	}

	_, err := spiffe.VerifyPeerCertificate(svidCerts, trustedCertificatePools, spiffe.ExpectAnyPeer())
	if nil != err {
		return nil, errors.New("Unable to validate SVID against trust chain - " + err.Error())
	}

	return svidCerts, nil
}

// ExtractCertificatesFromPem takes an array of bytes representing a PEM file
// and extracts any and all certificates located within that PEM data. This logic
// in this method has been borrowed from x509.CertPool::AppendCertsFromPEM which
// accepts the same argument, extracts, and appends the certificates to an
// x509.CertPool.
func ExtractCertificatesFromPem(pemCerts []byte) ([]*x509.Certificate){
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
