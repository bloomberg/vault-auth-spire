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
	"errors"
	"github.com/spiffe/go-spiffe/spiffe"
	"go.dev.bloomberg.com/bbgo/go-logrus"
)

type SvidVerifier struct {
	// map[domain] = pool of trusted certificates for domain
	trustedCertPools map[string]*x509.CertPool
}

func (verifier *SvidVerifier) Verify(svid string) ([]*x509.Certificate, error){

	logrus.Info(svid)

	svidCerts, err := verifier.constructCertificatesFromPem([]byte(svid))
	if err != nil {
		return nil, errors.New("Failed to parse SVID - " + err.Error())
	}

	if len(svidCerts) == 0 {
		return nil, errors.New("SVID is invalid")
	}

	_, err = spiffe.VerifyPeerCertificate(svidCerts, verifier.trustedCertPools, spiffe.ExpectAnyPeer())
	if nil != err {
		return nil, errors.New("Unable to validate SVID against trust chain - " + err.Error())
	}

	return svidCerts, nil
}