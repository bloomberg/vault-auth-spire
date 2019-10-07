package main

import (
	"crypto/x509"
)

type SvidValidator interface {
	Validate(svid string) (*x509.Certificate, error)
}
