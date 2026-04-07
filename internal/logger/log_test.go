package logger

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRedactionDefaultsOn(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	req.Header.Set("Authorization", "Bearer SECRET")
	req.Header.Set("Cookie", "sid=abc")
	req.Header.Set("X-Api-Key", "topsecret")
	req.Header.Set("X-Custom", "fine")

	cap := lg.LogRequest(req)
	io.Copy(io.Discard, req.Body)
	lg.FinalizeRequest(req, cap)

	out := buf.String()
	for _, secret := range []string{"Bearer SECRET", "sid=abc", "topsecret"} {
		if strings.Contains(out, secret) {
			t.Errorf("log unexpectedly contains %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, `\u003credacted\u003e`) {
		t.Errorf("expected <redacted> in output: %s", out)
	}
	if !strings.Contains(out, `"X-Custom":"fine"`) {
		t.Errorf("expected non-sensitive header preserved: %s", out)
	}
}

func TestRedactionCanBeDisabled(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf)
	lg.SetRedact(false)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer SECRET")
	cap := lg.LogRequest(req)
	io.Copy(io.Discard, req.Body)
	lg.FinalizeRequest(req, cap)

	if !strings.Contains(buf.String(), "Bearer SECRET") {
		t.Errorf("expected secret in plaintext when redaction off: %s", buf.String())
	}
}

func TestSubscriberCap(t *testing.T) {
	lg := New(io.Discard)
	cancels := make([]func(), 0, maxSubscribers)
	for i := 0; i < maxSubscribers; i++ {
		_, cancel, err := lg.Subscribe()
		if err != nil {
			t.Fatalf("subscribe %d: %v", i, err)
		}
		cancels = append(cancels, cancel)
	}
	if _, _, err := lg.Subscribe(); !errors.Is(err, ErrTooManySubscribers) {
		t.Errorf("expected ErrTooManySubscribers, got %v", err)
	}
	// Cancel one and ensure another can join.
	cancels[0]()
	_, cancel, err := lg.Subscribe()
	if err != nil {
		t.Errorf("expected re-subscribe after cancel, got %v", err)
	}
	cancel()
	for _, c := range cancels[1:] {
		c()
	}
}

func TestSubscriberReceivesRecord(t *testing.T) {
	lg := New(io.Discard)
	ch, cancel, err := lg.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	go lg.write(record{Kind: "request", Method: "GET", Host: "x"})

	select {
	case line := <-ch:
		if !strings.Contains(string(line), `"method":"GET"`) {
			t.Errorf("unexpected line: %s", line)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for record")
	}
}

func TestCapturedBodyTruncation(t *testing.T) {
	body := io.NopCloser(strings.NewReader(strings.Repeat("a", maxBody+1024)))
	cap := wrap(body)
	io.Copy(io.Discard, cap)
	if !cap.trunc {
		t.Error("expected truncation flag set")
	}
	if cap.buf.Len() != maxBody {
		t.Errorf("captured %d bytes, want %d", cap.buf.Len(), maxBody)
	}
}
