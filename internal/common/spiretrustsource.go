package common

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/workload"
)

// SpireTrustSource holds all necessary information to connect to a spire instance and store its certificates
type SpireTrustSource struct {
	domainURLs         map[string]string
	domainCertificates map[string][]*x509.Certificate
	spireClients       []*workload.X509SVIDClient
	certLocation       string
}

type certMap struct {
	Certs map[string][]string `json:"certs"`
}

type watcher struct {
	uri    string
	source *SpireTrustSource
}

// TrustedCertificates fulfills the TrustSource interface
func (s *SpireTrustSource) TrustedCertificates() map[string][]*x509.Certificate {
	return s.domainCertificates
}

// NewSpireTrustSource creates a new trust source with connectivity to one or more spire instances.
func NewSpireTrustSource(domainURLs map[string]string, certLocation string) (*SpireTrustSource, error) {
	source := SpireTrustSource{
		domainURLs:         domainURLs,
		domainCertificates: make(map[string][]*x509.Certificate, 0),
		certLocation:       certLocation,
	}

	if certLocation != "" {
		if err := source.parseCertFile(); err != nil {
			return nil, err
		}
	}

	if err := source.startWatchers(); err != nil {
		return nil, err
	}

	return &source, nil
}

// Stop stops all spire clients and writes out certs
func (s *SpireTrustSource) Stop() {
	for _, client := range s.spireClients {
		client.Stop()
	}
	s.writeCertFile()
}

func (s *SpireTrustSource) parseCertFile() error {
	file, err := appFS.OpenFile(s.certLocation, os.O_RDWR|os.O_CREATE, 600)
	if err != nil {
		return err
	}
	defer file.Close()

	fileDat, err := ioutil.ReadAll(file)
	if err != nil {
		return fmt.Errorf("could not read cert file: %v", err)
	}
	var certStruct certMap
	if err = json.Unmarshal(fileDat, &certStruct); err != nil {
		logrus.Warnf("Error unmarshaling cert file: %v\n", err)
	}
	for domain, encCerts := range certStruct.Certs {
		decodedCerts := make([]*x509.Certificate, 0)
		for _, certB64 := range encCerts {
			encCert, err := base64.StdEncoding.DecodeString(certB64)
			if err != nil {
				logrus.Warnf("Could not base 64 decode string: %v\n", err)
				continue
			}
			decodedCert, err := x509.ParseCertificate([]byte(encCert))
			if err != nil {
				logrus.Warnf("Could not decode certificate for domain %s: %v\n", domain, err)
				continue
			}
			decodedCerts = append(decodedCerts, decodedCert)
		}
		s.domainCertificates[domain] = decodedCerts
	}
	return nil
}

func (s *SpireTrustSource) writeCertFile() error {
	if s.certLocation == "" {
		return nil
	}

	certStruct := certMap{
		Certs: make(map[string][]string, 0),
	}

	for domain, certObjs := range s.TrustedCertificates() {
		toWrite := make([]string, 0)
		for _, certObj := range certObjs {
			marshalled := base64.StdEncoding.EncodeToString(certObj.Raw)
			toWrite = append(toWrite, string(marshalled))
		}
		certStruct.Certs[domain] = toWrite
	}

	finalData, _ := json.Marshal(certStruct)

	file, err := appFS.OpenFile(s.certLocation, os.O_RDWR|os.O_CREATE, 600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(finalData)
	if err != nil {
		return err
	}

	return nil
}

func (s *SpireTrustSource) startWatchers() error {
	for id, url := range s.domainURLs {
		opts := workload.WithAddr(url)
		watch := &watcher{
			uri:    id,
			source: s,
		}
		client, err := workload.NewX509SVIDClient(watch, opts)
		if err != nil {
			return err
		}
		s.spireClients = append(s.spireClients, client)

		logrus.Infof("Starting listener for %s.\n", id)
		go client.Start()
	}
	return nil
}

func (w *watcher) UpdateX509SVIDs(svids *workload.X509SVIDs) {
	w.source.domainCertificates[w.uri] = svids.Default().TrustBundle
	err := w.source.writeCertFile()
	if err != nil {
		logrus.Warnf("Error writing to cert file: %v\n", err)
	}
}

func (w *watcher) OnError(err error) {
	logrus.Errorf("Error encountered by watcher with uri %s: %v\n", w.uri, err)
}
