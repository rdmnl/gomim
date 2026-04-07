package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOriginAllowed(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		listen string
		want   bool
	}{
		{"no origin", "", "127.0.0.1:8081", true},
		{"localhost", "http://localhost:1234", "127.0.0.1:8081", true},
		{"loopback v4", "http://127.0.0.1:9999", "127.0.0.1:8081", true},
		{"loopback v6", "http://[::1]:9999", "127.0.0.1:8081", true},
		{"matches listen host", "http://10.0.0.5:8081", "10.0.0.5:8081", true},
		{"random remote", "http://evil.example", "127.0.0.1:8081", false},
		{"public ip", "http://8.8.8.8", "127.0.0.1:8081", false},
		{"malformed", "::not a url", "127.0.0.1:8081", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/events", nil)
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if got := originAllowed(r, c.listen); got != c.want {
				t.Errorf("originAllowed(origin=%q, listen=%q) = %v, want %v",
					c.origin, c.listen, got, c.want)
			}
		})
	}
}
