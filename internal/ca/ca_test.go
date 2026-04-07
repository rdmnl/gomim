package ca

import (
	"crypto/x509"
	"fmt"
	"testing"
)

func TestValidHost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"example.com:443", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"::1", true},
		{"foo_bar.local", true},
		{"xn--bcher-kva.example", true},
		{"", false},
		{"bad host", false},
		{"bad\nhost", false},
		{"bad\x00host", false},
		{"foo;rm -rf /", false},
		{string(make([]byte, 254)), false},
	}
	for _, c := range cases {
		if got := validHost(c.in); got != c.want {
			t.Errorf("validHost(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func newTestCA(t *testing.T) *CA {
	t.Helper()
	c, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return c
}

func TestLeafFor_CachesAndSigns(t *testing.T) {
	c := newTestCA(t)

	cert1, err := c.LeafFor("example.com")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	cert2, err := c.LeafFor("example.com")
	if err != nil {
		t.Fatalf("LeafFor (cached): %v", err)
	}
	if cert1 != cert2 {
		t.Errorf("expected cached leaf to be returned")
	}

	// Verify signature chains to our root.
	roots := x509.NewCertPool()
	roots.AddCert(c.cert)
	leaf, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:   roots,
		DNSName: "example.com",
	}); err != nil {
		t.Errorf("leaf failed to verify: %v", err)
	}
}

func TestLeafFor_RejectsInvalidHost(t *testing.T) {
	c := newTestCA(t)
	if _, err := c.LeafFor("bad host"); err == nil {
		t.Error("expected error for invalid host")
	}
}

func TestLeafFor_LRUEviction(t *testing.T) {
	c := newTestCA(t)

	// Mint maxCacheEntries+10 distinct hosts; the oldest should be evicted.
	for i := 0; i < maxCacheEntries+10; i++ {
		host := fmt.Sprintf("host-%d.example", i)
		if _, err := c.LeafFor(host); err != nil {
			t.Fatalf("LeafFor %s: %v", host, err)
		}
	}
	c.mu.Lock()
	size := c.lru.Len()
	cacheSize := len(c.cache)
	_, oldestStillThere := c.cache["host-0.example"]
	c.mu.Unlock()

	if size != maxCacheEntries || cacheSize != maxCacheEntries {
		t.Errorf("cache size = %d/%d, want %d", size, cacheSize, maxCacheEntries)
	}
	if oldestStillThere {
		t.Error("expected oldest entry to have been evicted")
	}
}

func TestRandomSerialUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := randomSerial()
		if err != nil {
			t.Fatal(err)
		}
		if seen[s.String()] {
			t.Fatalf("duplicate serial: %s", s)
		}
		seen[s.String()] = true
	}
}
