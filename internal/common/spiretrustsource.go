package common

import (
	"crypto/x509"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/workload"
)

// SpireTrustSource holds all necessary information to connect to a spire instance and store its certificates
type SpireTrustSource struct {
	domainURLs         map[string]string
	domainCertificates map[string][]*x509.Certificate
	fileBacking        *FileTrustSource
	spireClients       []*workload.X509SVIDClient
	certLocation       string
	updateChan         chan struct{}
	updateTimeout      time.Duration
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
		updateChan:         make(chan struct{}, 0),
		updateTimeout:      5 * time.Second,
	}

	if certLocation != "" {
		if err := source.initFileTrustSource(); err != nil {
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
}

func (s *SpireTrustSource) initFileTrustSource() error {
	re := regexp.MustCompile(`spiffe://(\S+)`)
	domainPaths := make(map[string][]string, 0)
	for uri := range s.domainURLs {
		matches := re.FindStringSubmatch(uri)
		if len(matches) < 2 {
			return fmt.Errorf("expected domain of form spiffe://<trust_domain> but got %s", uri)
		}
		domain := matches[1]
		if strings.Contains(domain, "/") {
			return fmt.Errorf("expected domain without slash but got %s", domain)
		}
		certPath := s.certLocation + "/" + domain + ".pem"
		domainPaths[uri] = []string{certPath}

		f, err := appFS.OpenFile(certPath, os.O_CREATE, 0600)
		if err != nil {
			return fmt.Errorf("error when trying to open file %s: %v", certPath, err)
		}
		f.Close()
	}

	var err error
	s.fileBacking, err = NewFileTrustSource(domainPaths)
	if err != nil {
		return err
	}

	s.domainCertificates = s.fileBacking.TrustedCertificates()

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
		client.Start()
	}
	return nil
}

func (w *watcher) UpdateX509SVIDs(svids *workload.X509SVIDs) {
	certs := svids.Default().TrustBundle
	w.source.domainCertificates[w.uri] = certs
	if w.source.certLocation != "" {
		certPath := w.source.fileBacking.domainPaths[w.uri][0]
		err := w.source.fileBacking.updateCertificates(certs, w.uri, certPath)
		if err != nil {
			logrus.Warnf("error writing to cert file: %v", err)
		}
	}
	select {
	case w.source.updateChan <- struct{}{}:
	case <-time.After(w.source.updateTimeout):
	}
}

func (w *watcher) OnError(err error) {
	logrus.Errorf("Error encountered by watcher with uri %s: %v\n", w.uri, err)
}
