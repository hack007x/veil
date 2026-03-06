// Package httpclient wraps net/http for vulnerability scanning use.
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Response is a simplified HTTP response.
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       string
	FinalURL   string
	Elapsed    time.Duration
}

// Client is the HTTP client used for all requests.
type Client struct {
	// Timeout and FollowRedirects may be changed between calls (per-request
	// overrides from the runner). Never embed them in inner — read at call-time.
	Timeout         time.Duration
	FollowRedirects bool
	VerifySSL       bool
	Proxy           string
	MaxRedirects    int

	inner *http.Client
}

// New creates a Client with the given settings.
func New(timeout time.Duration, followRedirects, verifySSL bool, proxy string) *Client {
	c := &Client{
		Timeout:         timeout,
		FollowRedirects: followRedirects,
		VerifySSL:       verifySSL,
		Proxy:           proxy,
		MaxRedirects:    10,
	}
	c.buildInner()
	return c
}

func (c *Client) buildInner() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !c.VerifySSL}, //nolint:gosec
		Proxy:           http.ProxyFromEnvironment,
	}
	if c.Proxy != "" {
		if proxyURL, err := url.Parse(c.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	redirectFn := func(req *http.Request, via []*http.Request) error {
		if !c.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= c.MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", c.MaxRedirects)
		}
		return nil
	}

	c.inner = &http.Client{
		Transport:     transport,
		CheckRedirect: redirectFn,
		// BUG FIX: Do NOT set Timeout here.
		//
		// http.Client.Timeout is a plain value copied at construction time.
		// runner.go updates r.client.Timeout before every request, but that
		// change never propagates to c.inner.Timeout (already frozen).
		//
		// Without -v the goroutine races into inner.Do() with no syscall
		// yield points; Go's netpoller gets starved just long enough for the
		// stale 10s timer to fire on a ~4s response.  With -v the Printf
		// write-syscalls park the goroutine, letting netpoller deliver the
		// response in time.
		//
		// Fix: inner.Timeout = 0, enforce deadline via context.WithTimeout
		// in Do(), reading the current c.Timeout on every call.
		Timeout: 0,
	}
}

// Do sends an HTTP request, enforcing c.Timeout via a per-call context.
func (c *Client) Do(method, rawURL string, headers map[string]string, body string) (*Response, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.inner.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	flatHeaders := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		flatHeaders[k] = resp.Header.Get(k)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    flatHeaders,
		Body:       string(respBody),
		FinalURL:   resp.Request.URL.String(),
		Elapsed:    elapsed,
	}, nil
}