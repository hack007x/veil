// Package engine defines the Scanner interface and engine registry.
//
// The default engine provides full scanning capabilities. Third-party or
// private engine implementations can replace it via engine.Use().
//
// To inject a custom engine, implement the Scanner interface and call
// engine.Use() in an init() function:
//
//	func init() {
//	    engine.Use(&MyCustomScanner{})
//	}
package engine

import (
	tpl "github.com/hack007x/veil/template"
)

// Scanner is the core vulnerability scanning interface.
//
// Any implementation must be safe for concurrent use from multiple goroutines.
type Scanner interface {
	// Scan executes a single template against a single target URL.
	Scan(t *tpl.PocTemplate, target string, opts ScanOptions) *tpl.ScanResult

	// Name returns the engine identifier (e.g. "veil-default", "veil-pro").
	Name() string

	// Version returns the engine version string.
	Version() string
}

// ScanOptions are per-scan runtime options passed to the engine.
type ScanOptions struct {
	Timeout         int    // request timeout in seconds
	FollowRedirects bool   // follow HTTP redirects
	VerifySSL       bool   // verify TLS certificates
	Proxy           string // HTTP/HTTPS proxy URL
	Verbose         bool   // enable verbose output
}

// ── Engine Registry ───────────────────────────────────────────────────────────

var current Scanner

// Use registers a Scanner implementation as the active engine.
// Calling Use(nil) resets to the default engine.
func Use(s Scanner) {
	if s == nil {
		current = nil
		return
	}
	current = s
}

// Get returns the active Scanner. If none has been registered via Use(),
// the built-in default engine is returned.
func Get() Scanner {
	if current == nil {
		current = newDefaultEngine()
	}
	return current
}

// IsDefault reports whether the active engine is the built-in default.
func IsDefault() bool {
	_, ok := Get().(*DefaultEngine)
	return ok
}
