// Package probe handles target URL normalization and liveness detection.
//
// Responsibilities:
//   - Normalize raw targets (bare domains, IPs, ports) into full URLs with scheme
//   - Prefer HTTPS over HTTP: try HTTPS first, fall back to HTTP only if HTTPS fails
//   - Concurrent liveness probing via HEAD request (GET fallback on 405)
//   - Any non-connection-error response (including 4xx/5xx) counts as alive
package probe

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ── URL Normalization ────────────────────────────────────────────────────────

// NormalizeTarget ensures the target has a scheme (http/https).
// It handles bare domains, domains with ports, IPs, IPs with ports, and
// full URLs that already have a scheme.
//
// Returns a list of candidate URLs to probe, ordered by priority:
//   - If the target already has a scheme → return as-is (single candidate).
//   - Otherwise → [https://host, http://host] (HTTPS preferred).
func NormalizeTarget(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	// Already has a scheme → return as-is
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return []string{raw}
	}

	// Strip accidental leading "//"
	raw = strings.TrimPrefix(raw, "//")

	// At this point raw could be:
	//   example.com
	//   example.com:8080
	//   example.com/path?query
	//   192.168.1.1
	//   192.168.1.1:8080
	//   [::1]:8080
	//
	// Use a temporary scheme so url.Parse can handle it correctly.
	tmp, err := url.Parse("probe://" + raw)
	if err != nil {
		// Fallback: just prepend schemes
		return []string{"https://" + raw, "http://" + raw}
	}

	host := tmp.Hostname()
	port := tmp.Port()
	pathAndQuery := tmp.RequestURI() // includes path + query + fragment

	// Build the host portion
	hostPart := host
	if port != "" {
		hostPart = net.JoinHostPort(host, port)
	}

	suffix := ""
	if pathAndQuery != "" && pathAndQuery != "/" {
		suffix = pathAndQuery
	}

	// Well-known port → single candidate with the obvious scheme
	if port == "443" {
		return []string{"https://" + hostPart + suffix}
	}
	if port == "80" {
		return []string{"http://" + hostPart + suffix}
	}

	// Default: try HTTPS first, then HTTP
	return []string{
		"https://" + hostPart + suffix,
		"http://" + hostPart + suffix,
	}
}

// ── Liveness Probe ───────────────────────────────────────────────────────────

// Result holds the outcome of probing a single raw target.
type Result struct {
	RawTarget string // original input (may lack scheme)
	AliveURL  string // the URL that responded (empty if dead)
	Alive     bool
	Error     string // reason for failure (used in verbose output)
}

// ResultCallback is called each time a single target finishes probing.
// It receives the result and a progress counter (1-based, total).
type ResultCallback func(result Result, done, total int)

// Targets takes a list of raw targets and probes each one for liveness.
// For targets without a scheme it tries HTTPS first, then HTTP.
// The onResult callback (if non-nil) is invoked in real time as each probe completes.
//
// Parameters:
//   - rawTargets:   the raw user-supplied targets
//   - timeout:      per-request timeout (maps to -timeout flag)
//   - concurrency:  number of parallel probes
//   - onResult:     callback for real-time output (may be nil)
func Targets(rawTargets []string, timeout time.Duration, concurrency int, onResult ResultCallback) []Result {
	results := make([]Result, len(rawTargets))
	total := len(rawTargets)

	// Shared HTTP client — skip TLS verify (we only care about reachability)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects during probe — a redirect means alive
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var doneCount int64
	var mu sync.Mutex

	for i, raw := range rawTargets {
		wg.Add(1)
		go func(idx int, rawTarget string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			candidates := NormalizeTarget(rawTarget)
			if len(candidates) == 0 {
				results[idx] = Result{
					RawTarget: rawTarget,
					Error:     "invalid target",
				}
				mu.Lock()
				doneCount++
				d := int(doneCount)
				mu.Unlock()
				if onResult != nil {
					onResult(results[idx], d, total)
				}
				return
			}

			var lastErr string
			for _, candidate := range candidates {
				alive, err := probeSingle(client, candidate)
				if alive {
					results[idx] = Result{
						RawTarget: rawTarget,
						AliveURL:  candidate,
						Alive:     true,
					}
					mu.Lock()
					doneCount++
					d := int(doneCount)
					mu.Unlock()
					if onResult != nil {
						onResult(results[idx], d, total)
					}
					return
				}
				if err != nil {
					lastErr = fmt.Sprintf("%s → %s", candidate, SummarizeError(err.Error()))
				}
			}

			// None of the candidates responded
			results[idx] = Result{
				RawTarget: rawTarget,
			}
			if lastErr != "" {
				results[idx].Error = lastErr
			} else {
				results[idx].Error = "all protocols failed"
			}

			mu.Lock()
			doneCount++
			d := int(doneCount)
			mu.Unlock()
			if onResult != nil {
				onResult(results[idx], d, total)
			}
		}(i, raw)
	}

	wg.Wait()
	return results
}

// probeSingle sends a HEAD request to check if a URL is alive.
// Falls back to GET on 405 Method Not Allowed.
// Any non-error response (including 4xx/5xx) means the target is alive.
func probeSingle(client *http.Client, targetURL string) (bool, error) {
	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()

	// 405 Method Not Allowed — retry with GET
	if resp.StatusCode == http.StatusMethodNotAllowed {
		req2, _ := http.NewRequest("GET", targetURL, nil)
		req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp2, err2 := client.Do(req2)
		if err2 != nil {
			// HEAD succeeded (got 405), so the target IS alive
			return true, nil
		}
		resp2.Body.Close()
	}

	return true, nil
}

// SummarizeError shortens common Go network error messages for cleaner output.
func SummarizeError(errMsg string) string {
	switch {
	case strings.Contains(errMsg, "connection refused"):
		return "connection refused"
	case strings.Contains(errMsg, "no such host"):
		return "DNS resolution failed"
	case strings.Contains(errMsg, "i/o timeout") || strings.Contains(errMsg, "context deadline exceeded"):
		return "timeout"
	case strings.Contains(errMsg, "certificate") || strings.Contains(errMsg, "tls"):
		return "TLS error"
	case strings.Contains(errMsg, "no route to host"):
		return "no route to host"
	case strings.Contains(errMsg, "network is unreachable"):
		return "network unreachable"
	default:
		if len(errMsg) > 80 {
			return errMsg[:80] + "…"
		}
		return errMsg
	}
}