package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

type rootCA struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	tlsCerts map[string]*tls.Certificate
	sync.RWMutex
}

func (ca *rootCA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	ca.RLock()
	tlsCert, found := ca.tlsCerts[hello.ServerName]
	ca.RUnlock()

	if found {
		return tlsCert, nil
	}

	cert, priv := ca.Cert(hello.ServerName)
	tlsCert = &tls.Certificate{
		Certificate: [][]byte{cert.Raw, ca.cert.Raw},
		PrivateKey:  priv,
	}

	ca.Lock()
	ca.tlsCerts[hello.ServerName] = tlsCert
	ca.Unlock()

	return tlsCert, nil
}

func (ca *rootCA) Cert(domain string) (*x509.Certificate, *ecdsa.PrivateKey) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to generate ecdsa key: %v", err)
		os.Exit(2)
	}
	publicKey := &privKey.PublicKey

	commonSubject := dummySubject(domain)

	cert := x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               commonSubject,
		NotAfter:              time.Now().AddDate(20, 0, 0),
		BasicConstraintsValid: true,
		IsCA:        false,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, ca.cert, publicKey, ca.key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create certificate: %v", err)
		os.Exit(2)
	}

	finalCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse created certificate: %v", err)
		os.Exit(2)
	}

	return finalCert, privKey
}

func LoadOrCreateRootCA(certFile, keyFile string) *rootCA {

	certExists := false
	keyExists := false

	if _, err := os.Stat(certFile); err == nil {
		certExists = true
	}

	if _, err := os.Stat(keyFile); err == nil {
		keyExists = true
	}

	if certExists && keyExists {
		return loadCA(certFile, keyFile)
	}

	// Clean up either file if it exists
	_ = os.Remove(certFile)
	_ = os.Remove(keyFile)

	return createCA(certFile, keyFile)
}

func loadCA(certFile string, keyFile string) *rootCA {

	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading root cert file: %v", err)
		os.Exit(2)
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		fmt.Fprintf(os.Stderr, "Error decoding PEM of root cert file: %v", err)
		os.Exit(2)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing root cert file: %v", err)
		os.Exit(2)
	}

	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading root private key file: %v", err)
		os.Exit(2)
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		fmt.Fprintf(os.Stderr, "Error decoding PEM of root private key file: %v", err)
		os.Exit(2)
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing root private key file: %v", err)
		os.Exit(2)
	}

	return &rootCA{
		cert:     cert,
		tlsCerts: make(map[string]*tls.Certificate, 10),
		key:      key,
	}
}

func createCA(certFile string, keyFile string) *rootCA {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to generate ecdsa key for root cert: %v", err)
		os.Exit(2)
	}
	publicKey := &privKey.PublicKey

	commonSubject := dummySubject("tlself.root")

	cert := x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               commonSubject,
		NotAfter:              time.Now().AddDate(20, 0, 0),
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		IsCA:        true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, &cert, publicKey, privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create root certificate: %v", err)
		os.Exit(2)
	}

	finalCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse created root certificate: %v", err)
		os.Exit(2)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open cert.pem for writing root cert: %v", err)
		os.Exit(2)
	}

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding root cert to pem block: %v", err)
		os.Exit(2)
	}

	err = certOut.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error closing root cert file: %v", err)
		os.Exit(2)
	}

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open key.pem for writing root key: %v", err)
		os.Exit(2)
	}

	err = pem.Encode(keyOut, pemBlockForKey(privKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding root private key to pem block: %v", err)
		os.Exit(2)
	}

	err = keyOut.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error closing root private key file: %v", err)
		os.Exit(2)
	}

	return &rootCA{
		cert:     finalCert,
		tlsCerts: make(map[string]*tls.Certificate, 10),
		key:      privKey,
	}
}

func pemBlockForKey(priv *ecdsa.PrivateKey) *pem.Block {
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to marshal ECDSA private key: %v", err)
		os.Exit(2)
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
}

func dummySubject(common string) pkix.Name {
	return pkix.Name{
		CommonName:         common,
		Organization:       []string{"No Corp"},
		OrganizationalUnit: []string{"WWW"},
		Locality:           []string{"YYY"},
		Country:            []string{"QQQ"},
		Province:           []string{"ZZZ"},
	}
}

func randSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate serial number: %s", err)
		os.Exit(2)
	}
	return serialNumber
}
