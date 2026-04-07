package ui

import (
	_ "embed"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/rdmnl/gomim/internal/logger"
)

//go:embed index.html
var indexHTML []byte

// Handler returns an http.Handler serving the live viewer UI and an SSE
// endpoint that streams JSONL records as they are produced.
//
// listenAddr is the address the UI server is bound to; it is used to
// enforce a same-origin-ish policy on the SSE endpoint so that captured
// traffic cannot be exfiltrated by an arbitrary website if the UI happens
// to be reachable over the network.
func Handler(lg *logger.Logger, listenAddr string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(indexHTML)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if !originAllowed(r, listenAddr) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		flusher.Flush()

		ch, cancel, err := lg.Subscribe()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer cancel()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-ch:
				if !ok {
					return
				}
				w.Write([]byte("data: "))
				if len(line) > 0 && line[len(line)-1] == '\n' {
					line = line[:len(line)-1]
				}
				w.Write(line)
				w.Write([]byte("\n\n"))
				flusher.Flush()
			}
		}
	})
	return mux
}

// originAllowed applies a conservative policy for the SSE endpoint:
//   - Requests with no Origin header are allowed (curl, EventSource from
//     same-origin pages does not always send Origin on older browsers).
//   - Requests with an Origin header must resolve to a loopback host.
//
// This blocks browser-initiated cross-origin reads from arbitrary websites
// if the user ever binds the UI to a non-loopback interface.
func originAllowed(r *http.Request, listenAddr string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	// Also allow exact match against the configured listen host (handles
	// cases where the user deliberately binds to a LAN IP and browses the
	// UI from that same IP).
	if lh, _, err := net.SplitHostPort(listenAddr); err == nil {
		if strings.EqualFold(lh, host) {
			return true
		}
	}
	return false
}
