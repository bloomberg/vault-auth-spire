package common

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/workload"
)

// SpireLoadState represents the current state of a Spire connection
type SpireLoadState int

const (
	Pending SpireLoadState = iota
	Loaded
	LoadedFromBackup
	Failed
)

// SpireEndpoint represents a single trust domain and its associated spire server connection
type SpireEndpoint struct {
	domain    string
	loadState SpireLoadState
	spireURL  string

	client *workload.X509SVIDClient
}

// SpireTrustSource holds all necessary information to connect to a spire instance and store its certificates
type SpireTrustSource struct {
	spireEndpoints map[string]*SpireEndpoint

	localBackupDir string

	updateChan    chan struct{}
	updateTimeout time.Duration

	domainCertificates map[string][]*x509.Certificate
	testing            bool
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
func NewSpireTrustSource(spireEndpointURLs map[string]string, localBackupDir string) (*SpireTrustSource, error) {
	source := &SpireTrustSource{
		spireEndpoints:     make(map[string]*SpireEndpoint, 0),
		localBackupDir:     localBackupDir,
		domainCertificates: make(map[string][]*x509.Certificate, 0),
		updateChan:         make(chan struct{}, 0),
		updateTimeout:      5 * time.Second,
	}

	re := regexp.MustCompile(`^spiffe://(\S+)$`)
	for trustDomain, spireURL := range spireEndpointURLs {
		localStoragePath := ""
		if localBackupDir != "" {
			matches := re.FindStringSubmatch(trustDomain)
			if len(matches) < 2 {
				return nil, fmt.Errorf("expected domain of form spiffe://<trust_domain> but got %s", trustDomain)
			}
			domain := matches[1]
			if strings.Contains(domain, "/") {
				return nil, fmt.Errorf("expected domain without slash but got %s", domain)
			}
			localStoragePath = filepath.Join(localBackupDir, domain+".pem")
		}

		client, err := workload.NewX509SVIDClient(
			&workloadWatcher{
				domain:           trustDomain,
				source:           source,
				localStoragePath: localStoragePath,
			},
			workload.WithAddr(spireURL),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to construct a new NewX509SVIDClient for %s: %v", spireURL, err)
		}

		source.spireEndpoints[trustDomain] = &SpireEndpoint{
			domain:    trustDomain,
			loadState: Pending,
			spireURL:  spireURL,
			client:    client,
		}
	}

	for _, spireEndpoint := range source.spireEndpoints {
		if err := spireEndpoint.client.Start(); err != nil {
			return nil, fmt.Errorf("failed to start NewX509SVIDClient for domain %s: %v", spireEndpoint.domain, err)
		}
	}

	return source, nil
}

// NewSpireTestSource creates a new spire trust source with the test flag on.
func NewSpireTestSource(spireEndpointURLs map[string]string, localBackupDir string) (*SpireTrustSource, error) {
	ts, err := NewSpireTrustSource(spireEndpointURLs, localBackupDir)
	if err != nil {
		return nil, err
	}
	ts.testing = true
	return ts, nil
}

// Stop stops all spire clients
func (s *SpireTrustSource) Stop() error {
	errs := make([]string, 0)
	for _, spireEndpoint := range s.spireEndpoints {
		if err := spireEndpoint.client.Stop(); err != nil {
			errs = append(errs, fmt.Sprintf("domain %s: %v", spireEndpoint.domain, err))
		}
	}

	if len(errs) != 0 {
		return fmt.Errorf("failed to stop NewX509SVIDClients: (%s)", strings.Join(errs, "),("))
	}

	return nil
}

func (w *workloadWatcher) UpdateX509SVIDs(svids *workload.X509SVIDs) {
	certs := svids.Default().TrustBundle
	w.source.domainCertificates[w.domain] = certs
	w.source.spireEndpoints[w.domain].loadState = Loaded

	if w.localStoragePath != "" {
		builder := strings.Builder{}
		for _, cert := range certs {
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			builder.Write(pem.EncodeToMemory(block))
		}
		file, err := appFS.OpenFile(w.localStoragePath, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"domain": w.domain,
				"path":   w.localStoragePath,
			}).Warnf("could not open backup file for trust domain: %v", err)
		} else {
			defer file.Close()
			_, err = file.WriteString(builder.String())
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"domain": w.domain,
					"path":   w.localStoragePath,
				}).Warnf("could not write to backup file for trust domain: %v", err)
			}
		}
	}

	if w.source.testing {
		select {
		case w.source.updateChan <- struct{}{}:
		case <-time.After(w.source.updateTimeout):
		}
	}
}

func (w *workloadWatcher) OnError(err error) {
	if w.source.spireEndpoints[w.domain].loadState == Pending {
		if w.localStoragePath != "" {
			domainPaths := map[string][]string{
				w.domain: []string{w.localStoragePath},
			}

			if fileTrustSource, err := NewFileTrustSource(domainPaths); err != nil {
				logrus.WithFields(logrus.Fields{
					"domain": w.domain,
				}).Warnf("could not load backup certs for from disk: %v", err)
				w.source.spireEndpoints[w.domain].loadState = Failed
			} else {
				w.source.domainCertificates[w.domain] = fileTrustSource.TrustedCertificates()[w.domain]
				w.source.spireEndpoints[w.domain].loadState = LoadedFromBackup
				logrus.WithFields(logrus.Fields{
					"domain": w.domain,
				}).Infof("loaded backup certs from disk")
			}
		} else {
			w.source.spireEndpoints[w.domain].loadState = Failed
			logrus.WithFields(logrus.Fields{
				"domain": w.domain,
			}).Warn("could not connect to spire server and local storage disabled")
		}
	} else {
		// if the state was already Loaded, LoadedFromBackup, or Failed then don't do anything
	}

	if w.source.testing {
		select {
		case w.source.updateChan <- struct{}{}:
		case <-time.After(w.source.updateTimeout):
		}
	}
}
