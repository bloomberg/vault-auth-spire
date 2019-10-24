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
	"github.com/sirupsen/logrus"
	"io/ioutil"
)

type TrustFileSource struct {
	domainPaths map[string][]string
	domainCertificates map[string][]*x509.Certificate
}

func NewTrustFileSource(domainPaths map[string][]string) (TrustFileSource, error){
	source := TrustFileSource{
		domainPaths: domainPaths,
		domainCertificates: make(map[string][]*x509.Certificate, 0),
	}

	if err := source.loadCertificates(); err != nil {
		return source, err
	}

	return source, nil
}

func (source *TrustFileSource) TrustedCertificates() map[string][]*x509.Certificate {
	return source.domainCertificates
}

func (source *TrustFileSource) loadCertificates() (error){
	for domain, paths := range source.domainPaths {
		domainCertificates := make([]*x509.Certificate, 0)

		for _, path := range paths {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				return errors.New("Failed to load certificates for domain " + domain + " from file " + path + " - " + err.Error())
			}

			certificates := ExtractCertificatesFromPem(data)
			if len(certificates) == 0 {
				logrus.Info("Did not load any certificates for domain " + domain + " from file " + path)
			}
			domainCertificates = append(domainCertificates, certificates...)
		}

		source.domainCertificates[domain] = domainCertificates
	}

	return nil
}
