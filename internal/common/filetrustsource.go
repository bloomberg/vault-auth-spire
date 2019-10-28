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

// FileTrustSource provides support for PEM-file based trust sources. This trust source
// should be provided a map of SPIFFE domains to PEM files containing trust CAs. Each
// domain can have 1 or more files assigned to it, and different domains can use the
// same PEM files. All certificates in the PEM file will be loaded.
type FileTrustSource struct {
	domainPaths map[string][]string
	domainCertificates map[string][]*x509.Certificate
}

// NewFileTrustSource constructs and loads an instance of FileTrustSource. This method
// will attempt to load all certificates for all domains. Failure to read a file will
// result in an error. Failure to parse a certificate from a PEM file will result in
// that certificate being ignored. If no certificates are loaded from a PEM file then
// an INFO message will be added to the log.
func NewFileTrustSource(domainPaths map[string][]string) (FileTrustSource, error){
	source := FileTrustSource{
		domainPaths: domainPaths,
		domainCertificates: make(map[string][]*x509.Certificate, 0),
	}

	if err := source.loadCertificates(); err != nil {
		return source, err
	}

	return source, nil
}

// TrustedCertificates returns our current maps of domains to certificates. This is a
// method to allow for thread safety if we decide to support refreshing of the files.
func (source *FileTrustSource) TrustedCertificates() map[string][]*x509.Certificate {
	return source.domainCertificates
}

func (source *FileTrustSource) loadCertificates() (error){
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
