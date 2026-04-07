package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rdmnl/gomim/internal/ca"
	"github.com/rdmnl/gomim/internal/logger"
)

func newProxy(t *testing.T) (*Proxy, *ca.CA, *logger.Logger) {
	t.Helper()
	c, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lg := logger.New(io.Discard)
	return New(c, lg), c, lg
}

// Plain-HTTP request through the proxy in reverse-proxy mode. Verifies
// header forwarding, body, and that hop-by-hop headers are stripped.
func TestProxy_ReverseHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Connection") != "" {
			t.Errorf("hop-by-hop Connection header leaked: %q", r.Header.Get("Connection"))
		}
		if r.Header.Get("X-Forwarded-Token") != "abc" {
			t.Errorf("missing forwarded header")
		}
		w.Header().Set("X-Upstream", "yes")
		io.WriteString(w, "hello reverse")
	}))
	defer upstream.Close()

	p, _, _ := newProxy(t)
	uURL, _ := url.Parse(upstream.URL)
	p.Reverse = uURL

	front := httptest.NewServer(p)
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/ping", nil)
	req.Header.Set("X-Forwarded-Token", "abc")
	req.Header.Set("Connection", "X-Drop-Me")
	req.Header.Set("X-Drop-Me", "should be gone")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "hello reverse") {
		t.Errorf("unexpected body: %s", body)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Errorf("missing upstream header")
	}
}

// CONNECT-based MITM round trip. The proxy mints a leaf cert for the
// upstream's host:port and decrypts the tunnel.
func TestProxy_ConnectMITM(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "hello mitm")
	}))
	defer upstream.Close()

	p, c, _ := newProxy(t)
	// Proxy must trust the test upstream's self-signed cert.
	upRoots := x509.NewCertPool()
	upRoots.AddCert(upstream.Certificate())
	p.Upstream.TLSClientConfig = &tls.Config{RootCAs: upRoots}

	front := httptest.NewServer(p)
	defer front.Close()
	frontURL, _ := url.Parse(front.URL)

	// Client trusts the proxy's MITM root.
	leaf, err := c.LeafFor("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(leaf.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(rootCert)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(frontURL),
			TLSClientConfig: &tls.Config{RootCAs: clientRoots},
			// Force HTTP/1.1 - h2 over hijacked conn complicates this test.
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
	}

	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/ping", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "hello mitm") {
		t.Errorf("unexpected body: %s", body)
	}
}
