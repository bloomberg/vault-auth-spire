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
	"go.dev.bloomberg.com/bbgo/go-logrus"
	"io/ioutil"
	"strconv"
)

type DomainTrustFileSource struct {
	DomainTrustSource
	Path string
}

func NewDomainTrustFileSource(domain, path string) (DomainTrustFileSource, error){
	source := DomainTrustFileSource{
		DomainTrustSource: DomainTrustSource{
			Domain: domain,
			Certificates: make([]*x509.Certificate, 0),
		},
		Path: path,
	}

	if err := source.loadCertificatesFromDisk(); err != nil {
		return nil, errors.New("Failed to load trusted certificates for domain '" + source.Domain + "'")
	}

	return source, nil
}

func (source *DomainTrustFileSource) load() (*DomainTrustFileSource, error) {
	if err := source.loadCertificatesFromDisk(); err != nil {
		return nil, err
	}

	return source, nil
}

// loadCertificatesFromDisk returns a slice of all certificates found in the file at path. If any fail
// to be parsed, or no certificagtes are found then verifier method returns an error
func (source *DomainTrustFileSource) loadCertificatesFromDisk() (error){
	logrus.Debug("Loading " + source.Path + " for domain " + source.Domain)

	data, err := ioutil.ReadFile(source.Path)
	if err != nil {
		return errors.New("Unable to open " + source.Path + " for reading")
	}

	certs, err := source.constructCertificatesFromPem(data)
	if err != nil {
		return err
	}

	source.certificates = certs
	if len(certs) == 0 {
		logrus.Info("Did not find any certificates in " + source.Path)
	}

	return nil
}

func (source *DomainTrustFileSource) constructCertificatesFromPem(pemData []byte) ([]*x509.Certificate, error){
	// Read all the pem blocks from the full file data, decode will return 1 at a time and nil when complete
	var pemBlocks []*pem.Block
	for {
		pemBlock, rest := pem.Decode(pemData)

		if pemBlock != nil {
			pemBlocks = append(pemBlocks, pemBlock)
		}

		if len(rest) == 0 {
			break
		}

		pemData = rest
		pemBlocks = append(pemBlocks, pemBlock)
	}

	var certs []*x509.Certificate
	for idx, block := range pemBlocks{
		if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, errors.New("Unable to parse certificate from pem - issue with pem block at index " + strconv.Itoa(idx) + " - " + err.Error())
		} else {
			certs = append(certs, cert)
		}
	}

	return certs, nil

}

func (verifier *SvidDiskVerifier) Verify(svid string) ([]*x509.Certificate, error){

	logrus.Info(svid)

	svidCerts, err := verifier.constructCertificatesFromPem([]byte(svid))
	if err != nil {
		return nil, errors.New("Failed to parse SVID - " + err.Error())
	}

	if len(svidCerts) == 0 {
		return nil, errors.New("SVID is invalid")
	}

	_, err = spiffe.VerifyPeerCertificate(svidCerts, verifier.domainCertPools, spiffe.ExpectAnyPeer())
	if nil != err {
		return nil, errors.New("Unable to validate SVID against trust chain - " + err.Error())
	}

	return svidCerts, nil
}