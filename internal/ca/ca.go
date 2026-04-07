package ca

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxCacheEntries bounds the per-host leaf certificate cache to prevent
// unbounded memory growth from attacker-controlled SNI values.
const maxCacheEntries = 1024

// serialLimit is 2^128, the upper bound for randomly-generated certificate
// serial numbers (RFC 5280 recommends at least 64 bits of entropy).
var serialLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, serialLimit)
}

// validHost returns true if host is a plausible DNS name or IP literal that
// is safe to embed in a certificate. Rejects empty, overlong, or
// control-character-laden values.
func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	// Strip optional port.
	if i := strings.LastIndex(host, ":"); i >= 0 {
		// Only strip if it looks like host:port, not an IPv6 literal.
		if !strings.Contains(host[:i], ":") {
			host = host[:i]
		}
	}
	if host == "" {
		return false
	}
	for _, r := range host {
		if r <= 0x20 || r == 0x7f {
			return false
		}
		if !(r == '.' || r == '-' || r == ':' || r == '_' ||
			(r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= 0x80)) {
			return false
		}
	}
	return true
}

// CA holds the root certificate authority used to mint per-host leaf certs.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	leafKey *ecdsa.PrivateKey // shared key for all leaves; fine for local MITM

	mu    sync.Mutex
	cache map[string]*list.Element
	lru   *list.List // front = most recently used
}

type cacheEntry struct {
	host string
	cert *tls.Certificate
}

// LoadOrCreate loads a root CA from dir, generating one if absent.
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		if err := generate(certPath, keyPath); err != nil {
			return nil, err
		}
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("invalid CA pem files")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     key,
		leafKey: leafKey,
		cache:   make(map[string]*list.Element),
		lru:     list.New(),
	}, nil
}

func generate(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "gomim Root CA",
			Organization: []string{"gomim"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(keyPath, "EC PRIVATE KEY", kb, 0o600)
}

func writePEM(path, typ string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: b})
}

// LeafFor returns (and caches) a TLS certificate for the given host, signed by the CA.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	if !validHost(host) {
		return nil, fmt.Errorf("invalid host %q", host)
	}

	c.mu.Lock()
	if el, ok := c.cache[host]; ok {
		c.lru.MoveToFront(el)
		cert := el.Value.(*cacheEntry).cert
		c.mu.Unlock()
		return cert, nil
	}
	c.mu.Unlock()

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &c.leafKey.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  c.leafKey,
		Leaf:        tmpl,
	}
	c.mu.Lock()
	if el, ok := c.cache[host]; ok {
		// Lost a race with another goroutine; reuse the existing entry.
		c.lru.MoveToFront(el)
		existing := el.Value.(*cacheEntry).cert
		c.mu.Unlock()
		return existing, nil
	}
	el := c.lru.PushFront(&cacheEntry{host: host, cert: cert})
	c.cache[host] = el
	for c.lru.Len() > maxCacheEntries {
		old := c.lru.Back()
		if old == nil {
			break
		}
		c.lru.Remove(old)
		delete(c.cache, old.Value.(*cacheEntry).host)
	}
	c.mu.Unlock()
	return cert, nil
}
