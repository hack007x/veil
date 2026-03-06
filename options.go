package veil

import (
	"os"
	"path/filepath"
	"strings"
)

// Options configures a Veil scanner instance.
type Options struct {
	// Network
	Timeout         int    // request timeout in seconds (default: 10)
	FollowRedirects bool   // follow HTTP redirects (default: true)
	VerifySSL       bool   // verify TLS certificates (default: false)
	Proxy           string // HTTP/HTTPS proxy URL

	// Scanning
	Concurrency int  // number of concurrent goroutines (default: 10)
	Verbose     bool // verbose output

	// Filters
	FilterIDs        []string // filter templates by ID
	FilterSeverities []string // filter templates by severity
	FilterTags       []string // filter templates by tag
	FilterCVEs       []string // filter templates by CVE
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:         10,
		FollowRedirects: true,
		VerifySSL:       false,
		Concurrency:     10,
	}
}

func (o *Options) applyDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = 10
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 10
	}
}

// collectPocFiles recursively collects .poc file paths from a path.
func collectPocFiles(path string) []string {
	var out []string

	info, err := os.Stat(path)
	if err != nil {
		matches, _ := filepath.Glob(path)
		for _, m := range matches {
			out = append(out, collectPocFiles(m)...)
		}
		return out
	}

	if info.IsDir() {
		_ = filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() && strings.HasSuffix(p, ".poc") {
				out = append(out, p)
			}
			return nil
		})
	} else if strings.HasSuffix(path, ".poc") {
		out = append(out, path)
	}

	return out
}
