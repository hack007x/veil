// Package veil is a template-driven vulnerability scanner SDK.
//
// Quick start:
//
//	v := veil.New(veil.DefaultOptions())
//	templates, _ := v.LoadTemplates("veil_poc/")
//	results := v.Scan([]string{"https://example.com"}, templates, nil)
//
// The default engine supports all features including multi-request chains,
// OOB callback verification, attack modes, and the complete matcher syntax.
//
// To inject a custom engine (e.g. a private enhanced build):
//
//	import _ "github.com/your/custom-engine"  // auto-registers via init()
package veil

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hack007x/veil/engine"
	"github.com/hack007x/veil/output"
	"github.com/hack007x/veil/parser"
	"github.com/hack007x/veil/probe"
	tpl "github.com/hack007x/veil/template"
	"github.com/hack007x/veil/validator"
)

// Version is the SDK version string.
const Version = "1.0.0"

// Veil is the main scanner instance.
type Veil struct {
	Options Options
}

// New creates a new Veil scanner with the given options.
func New(opts Options) *Veil {
	opts.applyDefaults()

	// Initialise OOB for the default engine
	if def, ok := engine.Get().(*engine.DefaultEngine); ok {
		def.InitOOB(opts.Verbose)
	}

	return &Veil{Options: opts}
}

// EngineName returns the name of the active scanning engine.
func (v *Veil) EngineName() string {
	return engine.Get().Name()
}

// EngineVersion returns the version of the active scanning engine.
func (v *Veil) EngineVersion() string {
	return engine.Get().Version()
}

// ── Template Loading ──────────────────────────────────────────────────────────

// ParseTemplate parses a single .poc file and returns the template.
func (v *Veil) ParseTemplate(path string) (*tpl.PocTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return parser.Parse(string(data), path)
}

// ParseTemplateContent parses .poc content from a string.
func (v *Veil) ParseTemplateContent(content, name string) (*tpl.PocTemplate, error) {
	return parser.Parse(content, name)
}

// LoadTemplates loads all .poc templates from paths (files, directories, or globs).
// Templates are filtered by the Options' Severity, Tags, CVE, and ID filters.
func (v *Veil) LoadTemplates(paths ...string) ([]*tpl.PocTemplate, error) {
	var pocPaths []string
	for _, p := range paths {
		collected := collectPocFiles(p)
		pocPaths = append(pocPaths, collected...)
	}

	if len(pocPaths) == 0 {
		return nil, fmt.Errorf("no .poc files found in: %v", paths)
	}

	var templates []*tpl.PocTemplate
	for _, p := range pocPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		t, err := parser.Parse(string(data), p)
		if err != nil {
			continue
		}
		if strings.TrimSpace(t.Metadata.ID) == "" ||
			strings.TrimSpace(t.Metadata.Name) == "" ||
			strings.TrimSpace(t.Metadata.Author) == "" ||
			strings.TrimSpace(t.Metadata.Severity) == "" {
			continue
		}
		if !v.matchFilters(t) {
			continue
		}
		templates = append(templates, t)
	}

	return templates, nil
}

// ValidateTemplate validates a parsed template and returns a validation report.
func (v *Veil) ValidateTemplate(t *tpl.PocTemplate, rawContent string) *validator.Report {
	return validator.ValidateRaw(t, rawContent)
}

// ── Scanning ──────────────────────────────────────────────────────────────────

// ScanResult is an alias for template.ScanResult.
type ScanResult = tpl.ScanResult

// ResultCallback is called each time a single scan completes.
type ResultCallback func(result *ScanResult, done, total int)

// Scan runs all templates against all targets and returns the results.
// Targets are automatically probed for liveness before scanning.
// The optional onResult callback is invoked in real time as each scan completes.
func (v *Veil) Scan(rawTargets []string, templates []*tpl.PocTemplate, onResult ResultCallback) []*ScanResult {
	if len(rawTargets) == 0 || len(templates) == 0 {
		return nil
	}

	// ── Probe targets ─────────────────────────────────────────────────────
	probeTimeout := time.Duration(v.Options.Timeout) * time.Second
	aliveResults := probe.Targets(rawTargets, probeTimeout, v.Options.Concurrency, nil)

	var targets []string
	for _, r := range aliveResults {
		if r.Alive {
			targets = append(targets, r.AliveURL)
		}
	}
	if len(targets) == 0 {
		return nil
	}

	// ── Concurrent scan ───────────────────────────────────────────────────
	type job struct {
		target   string
		template *tpl.PocTemplate
	}

	scanner := engine.Get()
	scanOpts := engine.ScanOptions{
		Timeout:         v.Options.Timeout,
		FollowRedirects: v.Options.FollowRedirects,
		VerifySSL:       v.Options.VerifySSL,
		Proxy:           v.Options.Proxy,
		Verbose:         v.Options.Verbose,
	}

	jobs := make(chan job, v.Options.Concurrency*2)
	total := len(targets) * len(templates)

	var (
		resultsMu sync.Mutex
		results   []*ScanResult
		wg        sync.WaitGroup
		done      int
		doneMu    sync.Mutex
	)

	for i := 0; i < v.Options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				res := scanner.Scan(j.template, j.target, scanOpts)

				resultsMu.Lock()
				results = append(results, res)
				resultsMu.Unlock()

				doneMu.Lock()
				done++
				d := done
				doneMu.Unlock()

				if onResult != nil {
					onResult(res, d, total)
				}
			}
		}()
	}

	for _, target := range targets {
		for _, t := range templates {
			jobs <- job{target: target, template: t}
		}
	}
	close(jobs)
	wg.Wait()

	return results
}

// ScanOne runs a single template against a single target URL.
// No liveness probing — the target is assumed to be reachable.
func (v *Veil) ScanOne(target string, t *tpl.PocTemplate) *ScanResult {
	scanner := engine.Get()
	return scanner.Scan(t, target, engine.ScanOptions{
		Timeout:         v.Options.Timeout,
		FollowRedirects: v.Options.FollowRedirects,
		VerifySSL:       v.Options.VerifySSL,
		Proxy:           v.Options.Proxy,
		Verbose:         v.Options.Verbose,
	})
}

// ── Report Generation ─────────────────────────────────────────────────────────

// SaveJSON writes vulnerable results to a JSON file.
func (v *Veil) SaveJSON(results []*ScanResult, path string) error {
	return output.SaveJSON(results, path)
}

// SaveHTML writes vulnerable results to an HTML report.
func (v *Veil) SaveHTML(results []*ScanResult, path string) error {
	return output.SaveHTML(results, path)
}

// ── Probing ───────────────────────────────────────────────────────────────────

// Probe checks target liveness without scanning.
// Returns only alive URLs (scheme normalised, HTTPS preferred).
func (v *Veil) Probe(rawTargets []string) []string {
	timeout := time.Duration(v.Options.Timeout) * time.Second
	results := probe.Targets(rawTargets, timeout, v.Options.Concurrency, nil)
	var alive []string
	for _, r := range results {
		if r.Alive {
			alive = append(alive, r.AliveURL)
		}
	}
	return alive
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (v *Veil) matchFilters(t *tpl.PocTemplate) bool {
	o := v.Options
	if len(o.FilterIDs) > 0 && !containsIC(o.FilterIDs, t.Metadata.ID) {
		return false
	}
	if len(o.FilterSeverities) > 0 && !containsIC(o.FilterSeverities, t.Metadata.Severity) {
		return false
	}
	if len(o.FilterTags) > 0 && !anyTagMatch(t.Metadata.Tags, o.FilterTags) {
		return false
	}
	if len(o.FilterCVEs) > 0 && !containsIC(o.FilterCVEs, t.Metadata.CVE) {
		return false
	}
	return true
}

func containsIC(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func anyTagMatch(templateTags, filterTags []string) bool {
	for _, ft := range filterTags {
		for _, tt := range templateTags {
			if strings.EqualFold(tt, ft) {
				return true
			}
		}
	}
	return false
}
