package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// maxSubscribers caps concurrent live-viewer subscribers to bound memory.
const maxSubscribers = 32

// redactedHeaders is a case-insensitive set of header names whose values
// are replaced with "<redacted>" before being written to the log. These
// commonly carry credentials or session material.
var redactedHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-auth-token":        {},
	"x-amz-security-token": {},
	"x-goog-api-key":      {},
}

// ErrTooManySubscribers is returned by Subscribe when the cap is reached.
var ErrTooManySubscribers = errors.New("too many subscribers")

// Logger writes structured JSON request/response records.
type Logger struct {
	mu          sync.Mutex
	out         io.Writer
	subscribers map[chan []byte]struct{}
	redact      bool
}

func New(out io.Writer) *Logger {
	if out == nil {
		out = os.Stdout
	}
	return &Logger{
		out:         out,
		subscribers: make(map[chan []byte]struct{}),
		redact:      true,
	}
}

// SetRedact toggles redaction of sensitive headers (Authorization, Cookie,
// etc.). Redaction is enabled by default.
func (l *Logger) SetRedact(on bool) {
	l.mu.Lock()
	l.redact = on
	l.mu.Unlock()
}

// Subscribe returns a channel that receives every JSON record line (with
// trailing newline) as it is written. The caller must call the returned
// cancel func to unsubscribe and drain.
func (l *Logger) Subscribe() (<-chan []byte, func(), error) {
	ch := make(chan []byte, 64)
	l.mu.Lock()
	if len(l.subscribers) >= maxSubscribers {
		l.mu.Unlock()
		return nil, nil, ErrTooManySubscribers
	}
	l.subscribers[ch] = struct{}{}
	l.mu.Unlock()
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			l.mu.Lock()
			delete(l.subscribers, ch)
			l.mu.Unlock()
			close(ch)
		})
	}
	return ch, cancel, nil
}

type record struct {
	Time       string            `json:"time"`
	Kind       string            `json:"kind"` // "request" | "response"
	Method     string            `json:"method,omitempty"`
	Host       string            `json:"host,omitempty"`
	Path       string            `json:"path,omitempty"`
	Status     int               `json:"status,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	BodyTrunc  bool              `json:"body_truncated,omitempty"`
	DurationMs int64             `json:"duration_ms,omitempty"`
}

const maxBody = 64 * 1024

func flatten(h http.Header, redact bool) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) == 0 {
			continue
		}
		if redact {
			if _, r := redactedHeaders[strings.ToLower(k)]; r {
				m[k] = "<redacted>"
				continue
			}
		}
		m[k] = v[0]
	}
	return m
}

func (l *Logger) write(r record) {
	r.Time = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(r)
	line := append(b, '\n')
	l.mu.Lock()
	l.out.Write(line)
	for ch := range l.subscribers {
		select {
		case ch <- line:
		default:
			// slow consumer; drop record for this subscriber
		}
	}
	l.mu.Unlock()
}

// TeeBody wraps a request/response body so the bytes flow through unchanged
// while a bounded copy is captured for logging.
type captured struct {
	io.ReadCloser
	buf   bytes.Buffer
	limit int
	trunc bool
}

func (c *captured) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		remaining := c.limit - c.buf.Len()
		if remaining > 0 {
			w := n
			if w > remaining {
				w = remaining
				c.trunc = true
			}
			c.buf.Write(p[:w])
		} else if n > 0 {
			c.trunc = true
		}
	}
	return n, err
}

func wrap(rc io.ReadCloser) *captured {
	return &captured{ReadCloser: rc, limit: maxBody}
}

// LogRequest captures a request. Returns the captured body holder so the
// caller can finalize logging after the body has been streamed upstream.
func (l *Logger) LogRequest(req *http.Request) *captured {
	cap := wrap(req.Body)
	req.Body = cap
	return cap
}

func (l *Logger) FinalizeRequest(req *http.Request, cap *captured) {
	l.mu.Lock()
	redact := l.redact
	l.mu.Unlock()
	l.write(record{
		Kind:      "request",
		Method:    req.Method,
		Host:      req.Host,
		Path:      req.URL.RequestURI(),
		Headers:   flatten(req.Header, redact),
		Body:      cap.buf.String(),
		BodyTrunc: cap.trunc,
	})
}

func (l *Logger) LogResponse(resp *http.Response) *captured {
	cap := wrap(resp.Body)
	resp.Body = cap
	return cap
}

func (l *Logger) FinalizeResponse(resp *http.Response, cap *captured, start time.Time) {
	l.mu.Lock()
	redact := l.redact
	l.mu.Unlock()
	l.write(record{
		Kind:       "response",
		Host:       resp.Request.Host,
		Path:       resp.Request.URL.RequestURI(),
		Status:     resp.StatusCode,
		Headers:    flatten(resp.Header, redact),
		Body:       cap.buf.String(),
		BodyTrunc:  cap.trunc,
		DurationMs: time.Since(start).Milliseconds(),
	})
}
