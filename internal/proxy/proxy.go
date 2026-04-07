package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/rdmnl/gomim/internal/ca"
	"github.com/rdmnl/gomim/internal/logger"
)

// Proxy is an HTTP/HTTPS MITM proxy.
type Proxy struct {
	CA     *ca.CA
	Logger *logger.Logger

	// Reverse, if non-nil, makes the proxy act as a reverse proxy: any
	// non-CONNECT request with a non-absolute URL is rewritten to this
	// Upstream (scheme + host). Used with ANTHROPIC_BASE_URL.
	Reverse *url.URL

	Upstream *http.Transport
}

func New(c *ca.CA, l *logger.Logger) *Proxy {
	return &Proxy{
		CA:     c,
		Logger: l,
		Upstream: &http.Transport{
			Proxy:                 nil,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleHTTP forwards a plain HTTP request.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		if p.Reverse == nil {
			http.Error(w, "proxy requires absolute URL", http.StatusBadRequest)
			return
		}
		// Reverse-proxy mode: rewrite the request URL to the configured Upstream.
		r.URL.Scheme = p.Reverse.Scheme
		r.URL.Host = p.Reverse.Host
		r.Host = p.Reverse.Host
	}
	p.forward(w, r)
}

// handleConnect performs a MITM TLS termination for the CONNECT target.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		return
	}

	tlsCfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			}
			return p.CA.LeafFor(name)
		},
		NextProtos: []string{"h2", "http/1.1"},
	}

	tlsConn := tls.Server(clientConn, tlsCfg)
	// NB: r.Context() is unreliable after Hijack - use a fresh context with
	// a bounded handshake timeout.
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer hsCancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		log.Printf("tls handshake %s: %v", host, err)
		return
	}
	defer tlsConn.Close()

	// Serve HTTP/1.1 or HTTP/2 over the decrypted conn, dispatching each
	// request through forward(). http.Server handles ALPN-negotiated h2.
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = r.Host
			req.RequestURI = ""
			p.forward(w, req)
		}),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// Enable h2 on this server so ALPN-negotiated HTTP/2 from the client works.
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		log.Printf("http2 configure: %v", err)
		return
	}

	// Dispatch based on the ALPN-negotiated protocol.
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol == "h2" {
		srv.TLSNextProto["h2"](srv, tlsConn, srv.Handler)
		return
	}
	// Wrap the listener so that closing the served connection also closes
	// the listener - otherwise srv.Serve would return immediately on the
	// second Accept (io.EOF), letting handleConnect's deferred Close race
	// with the still-running handler goroutine.
	lst := newSingleConnListener(tlsConn)
	_ = srv.Serve(lst)
	<-lst.done
}

func (p *Proxy) forward(w http.ResponseWriter, req *http.Request) {
	start := time.Now()

	out := req.Clone(context.Background())
	out.RequestURI = ""
	removeHopHeaders(out.Header)

	reqCap := p.Logger.LogRequest(out)

	resp, err := p.Upstream.RoundTrip(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	resp.Request = out

	p.Logger.FinalizeRequest(out, reqCap)

	removeHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	respCap := p.Logger.LogResponse(resp)
	if f, ok := w.(http.Flusher); ok {
		// Stream-friendly copy for SSE etc.
		buf := make([]byte, 16*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					break
				}
				f.Flush()
			}
			if rerr != nil {
				break
			}
		}
	} else {
		_, _ = io.Copy(w, resp.Body)
	}
	p.Logger.FinalizeResponse(resp, respCap, start)
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive",
	"Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
}

// singleConnListener exposes a single net.Conn as a net.Listener so that
// http.Server.Serve can drive HTTP/1.1 over our hijacked TLS conn. The
// listener returns the wrapped conn exactly once, then blocks on Accept
// until Close (or the conn itself) is closed; this ensures srv.Serve
// outlives the handler goroutine.
type singleConnListener struct {
	ch   chan net.Conn
	done chan struct{}
	addr net.Addr
	once sync.Once
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	l := &singleConnListener{
		ch:   make(chan net.Conn, 1),
		done: make(chan struct{}),
		addr: c.LocalAddr(),
	}
	// Wrap the conn so that closing it also closes the listener - that
	// happens when http.Server's per-conn handler finishes.
	l.ch <- &closeNotifyConn{Conn: c, l: l}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, io.EOF
	}
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.addr }

type closeNotifyConn struct {
	net.Conn
	l    *singleConnListener
	once sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.l.Close() })
	return err
}
