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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/spiffe/go-spiffe/spiffe"
	"go.dev.bloomberg.com/bbgo/go-logrus"
	"io/ioutil"
	"strconv"
)

func NewSvidDiskValidator(settings *FileSourceOfTrustSettings) (*SvidDiskValidator, error){
	validator := new(SvidDiskValidator)

	return validator.initialize(settings)
}

type SvidDiskValidator struct {
	domainCertPools map[string]*x509.CertPool
}

func (validator *SvidDiskValidator) initialize(settings *FileSourceOfTrustSettings) (*SvidDiskValidator, error) {
	validator.domainCertPools = make(map[string]*x509.CertPool)

	for domain, caPaths := range settings.domains{
		// CHECK: is it alright if a pool has 0 certs in it? Can happen if settings have an empty list of paths
		validator.domainCertPools[domain] = x509.NewCertPool()

		for _,caPath := range caPaths {
			logrus.Info("Loading " + caPath + " for domain " + domain)
			if certs, err := validator.loadCertificatesFromDisk(caPath); err != nil {
				return nil, errors.New("Failed to load certificates from " + caPath + " for domain '" + domain + "' - " + err.Error())
			} else {
				for _,cert := range certs {
					validator.domainCertPools[domain].AddCert(cert)
				}
			}
		}
	}

	return validator, nil
}

// loadCertificatesFromDisk returns a slice of all certificates found in the file at path. If any fail
// to be parsed, or no certificagtes are found then validator method returns an error
func (validator * SvidDiskValidator) loadCertificatesFromDisk(path string) ([]*x509.Certificate, error){
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New("Unable to open " + path + " for reading")
	}

	// Read all the pem blocks from the full file data, decode will return 1 at a time and nil when complete
	var pemBlocks []*pem.Block
	for {
		pemBlock, rest := pem.Decode(data)

		if pemBlock == nil {
			break
		}

		data = rest
		pemBlocks = append(pemBlocks, pemBlock)
	}

	if len(pemBlocks) == 0 {
		return nil, errors.New("Did not find any certificates in " + path)
	}

	var certs []*x509.Certificate
	for idx, block := range pemBlocks{
		if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, errors.New("Unable to parse certificate from " + path + " - issue with pem block at index " + strconv.Itoa(idx) + " - " + err.Error())
		} else {
			certs = append(certs, cert)
		}
	}

	return certs, nil
}

func (validator *SvidDiskValidator) Validate(svid string) (*x509.Certificate, error){

	logrus.Info(svid)

	// CHECK: should we accept SVIDs with multiple pem blocks in them? I don't think so, but
	// open for discussion
	block, _ := pem.Decode([]byte(svid))
	if block == nil {
		return nil, errors.New("Unable to decode certificate PEM from provided SVID")
	}

	svidCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("Unable to parse certificate from provided SVID")
	}

	_, err = spiffe.VerifyPeerCertificate([]*x509.Certificate{svidCert}, validator.domainCertPools, spiffe.ExpectAnyPeer())
	if nil != err {
		return nil, errors.New("Unable to validate SVID against trust chain - " + err.Error())
	}

	return svidCert, nil
}