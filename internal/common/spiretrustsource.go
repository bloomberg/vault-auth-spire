package common

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/workload"
)

type SpireLoadState int

const (
	Pending SpireLoadState = iota
	Loaded
	LoadedFromBackup
	Failed
)

// SpireTrustSource holds all necessary information to connect to a spire instance and store its certificates
type SpireEndpoint struct {
	domain    string
	loadState SpireLoadState
	spireUrl  string

	client *workload.X509SVIDClient
}
type SpireTrustSource struct {
	spireEndpoints map[string]*SpireEndpoint

	localBackupDir string

	updateChan    chan struct{}
	updateTimeout time.Duration

	domainCertificates map[string][]*x509.Certificate
}

type certMap struct {
	Certs map[string][]string `json:"certs"`
}

type workloadWatcher struct {
	domain           string
	source           *SpireTrustSource
	localStoragePath string
}

// TrustedCertificates fulfills the TrustSource interface
func (s *SpireTrustSource) TrustedCertificates() map[string][]*x509.Certificate {
	return s.domainCertificates
}

// NewSpireTrustSource creates a new trust source with connectivity to one or more spire instances.
func NewSpireTrustSource(spireEndpointUrls map[string]string, localBackupDir string) (*SpireTrustSource, error) {
	source := &SpireTrustSource{
		spireEndpoints:     make(map[string]*SpireEndpoint, 0),
		localBackupDir:     localBackupDir,
		domainCertificates: make(map[string][]*x509.Certificate, 0),
		updateChan:         make(chan struct{}, 0),
		updateTimeout:      5 * time.Second,
	}

	for domain, spireUrl := range spireEndpointUrls {
		localStoragePath := ""
		if localBackupDir != "" {
			localStoragePath = "" // TODO: pull out from domain
		}

		client, err := workload.NewX509SVIDClient(
			&workloadWatcher{
				domain:           domain,
				source:           source,
				localStoragePath: localStoragePath,
			},
			workload.WithAddr(spireUrl),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to construct a new NewX509SVIDClient for %s - %v", spireUrl, err)
		}

		source.spireEndpoints[domain] = &SpireEndpoint{
			domain:    domain,
			loadState: Pending,
			spireUrl:  spireUrl,
			client:    client,
		}
	}

	for _, spireEndpoint := range source.spireEndpoints {
		if err := spireEndpoint.client.Start(); err != nil {
			return nil, fmt.Errorf("failed to start NewX509SVIDClient for domain %s - %v", spireEndpoint.domain, err)
		}
	}

	return source, nil
}

// Stop stops all spire clients
func (s *SpireTrustSource) Stop() error {
	errs := make([]string, 0)
	for _, spireEndpoint := range s.spireEndpoints {
		if err := spireEndpoint.client.Stop(); err != nil {
			errs = append(errs, fmt.Sprintf("domain %s - %v", spireEndpoint.domain, err))
		}
	}

	if len(errs) != 0 {
		return fmt.Errorf("failed to stop NewX509SVIDClients: (%s)", strings.Join(errs, "),("))
	}

	return nil
}

func (w *workloadWatcher) UpdateX509SVIDs(svids *workload.X509SVIDs) {

	// TODO:
	// 1. Pull out certs from passed in svids and update w.source.domainCertificates
	// 2. Update w.source.spireEndpoints[w.url].loadState = Loaded
	// 3. write to w.source.updateChan
	//
	// if w.source.localBackupPath != ""
	//   4. write certs to storage path from w.source.localBackupPath/[domain without spiffe:// part].pem

	//certs := svids.Default().TrustBundle
	//w.source.domainCertificates[w.uri] = certs
	//if w.source.certLocation != "" {
	//	certPath := w.source.fileBacking.domainPaths[w.uri][0]
	//	err := w.source.fileBacking.updateCertificates(certs, w.uri, certPath)
	//	if err != nil {
	//		logrus.Warnf("error writing to cert file: %v", err)
	//	}
	//}
	//select {
	//case w.source.updateChan <- struct{}{}:
	//case <-time.After(w.source.updateTimeout):
	//}
}

func (w *workloadWatcher) OnError(err error) {
	if w.source.spireEndpoints[w.domain].loadState == Pending {
		if w.localStoragePath != "" {
			domainPaths := map[string][]string{
				w.domain: []string{w.localStoragePath},
			}

			if fileTrustSource, err := NewFileTrustSource(domainPaths); err != nil {
				// TODO: log error
				w.source.spireEndpoints[w.domain].loadState = Failed
			} else {
				// TODO:
				// 1. Pull out certs from fileTrustSource and update w.source.domainCertificates
				// 2. Update w.source.spireEndpoints[w.url].loadState = Loaded
			}
		} else {
			// TODO: log error
			w.source.spireEndpoints[w.domain].loadState = Failed
		}
	}

	// if the state was already Loaded, LoadedFromBackup, or Failed then don't do anything
}
