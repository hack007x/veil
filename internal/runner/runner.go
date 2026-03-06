// Package runner executes a PocTemplate against a single target URL.
package runner

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hack007x/veil/internal/extractor"
	"github.com/hack007x/veil/internal/httpclient"
	"github.com/hack007x/veil/internal/matcher"
	"github.com/hack007x/veil/internal/oob"
	"github.com/hack007x/veil/output"
	"github.com/hack007x/veil/internal/resolver"
	tpl "github.com/hack007x/veil/template"
)

// Options controls runner behaviour.
type Options struct {
	Timeout         time.Duration
	FollowRedirects bool
	VerifySSL       bool
	Proxy           string
	Verbose         bool
	OOBManager      *oob.Manager // managed externally — shared across all runners
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:         10 * time.Second,
		FollowRedirects: true,
		VerifySSL:       false,
	}
}

// Runner executes templates.
type Runner struct {
	opts      Options
	client    *httpclient.Client
	extractor *extractor.Engine
}

// New creates a Runner with the given options.
func New(opts Options) *Runner {
	return &Runner{
		opts:      opts,
		client:    httpclient.New(opts.Timeout, opts.FollowRedirects, opts.VerifySSL, opts.Proxy),
		extractor: extractor.New(),
	}
}

// Run executes template t against target and returns the result.
// If the template has list variables, it iterates over all combinations
// according to the attack mode.
//
// Only the combination that triggers a vulnerability is kept in the report.
// For enumeration scenarios (e.g. username wordlists), this avoids flooding
// the HTML report with hundreds of request/response pairs.
func (r *Runner) Run(t *tpl.PocTemplate, target string) *tpl.ScanResult {
	// Check if there are any list variables
	if len(t.ListVars) == 0 {
		return r.runOnce(t, target)
	}

	// Generate variable combinations based on attack mode
	combos := generateCombinations(t.ListVars, t.AttackMode)
	if len(combos) == 0 {
		return r.runOnce(t, target)
	}

	// Try each combination until one succeeds
	var lastResult *tpl.ScanResult
	for _, combo := range combos {
		// Create a copy of the template with this combination's values
		tcopy := copyTemplateWithVars(t, combo)
		result := r.runOnce(tcopy, target)
		if result.Vulnerable {
			// Record which variable values triggered the match
			result.MatchedVars = combo
			return result
		}
		lastResult = result
	}

	if lastResult != nil {
		return lastResult
	}
	return r.runOnce(t, target)
}

// copyTemplateWithVars creates a shallow copy of the template with overridden variable values.
func copyTemplateWithVars(t *tpl.PocTemplate, overrides map[string]string) *tpl.PocTemplate {
	tcopy := *t
	tcopy.Variables = make(map[string]string, len(t.Variables))
	for k, v := range t.Variables {
		tcopy.Variables[k] = v
	}
	for k, v := range overrides {
		tcopy.Variables[k] = v
	}
	return &tcopy
}

// generateCombinations produces all variable value sets to try.
func generateCombinations(listVars map[string][]string, mode tpl.AttackMode) []map[string]string {
	if len(listVars) == 0 {
		return nil
	}

	// Collect variable names and their values in stable order
	var names []string
	var valueSets [][]string
	for name, vals := range listVars {
		if len(vals) > 0 {
			names = append(names, name)
			valueSets = append(valueSets, vals)
		}
	}
	if len(names) == 0 {
		return nil
	}

	switch mode {
	case tpl.AttackPitchfork:
		return pitchforkCombos(names, valueSets)
	case tpl.AttackClusterbomb:
		return clusterbombCombos(names, valueSets)
	default: // sniper
		return sniperCombos(names, valueSets)
	}
}

// sniperCombos: iterate each variable independently, others stay at first value.
func sniperCombos(names []string, valueSets [][]string) []map[string]string {
	var combos []map[string]string

	// Build default values (first value of each)
	defaults := make(map[string]string, len(names))
	for i, name := range names {
		defaults[name] = valueSets[i][0]
	}

	for varIdx, name := range names {
		for _, val := range valueSets[varIdx] {
			combo := make(map[string]string, len(names))
			for k, v := range defaults {
				combo[k] = v
			}
			combo[name] = val
			combos = append(combos, combo)
		}
	}

	return dedup(combos)
}

// pitchforkCombos: zip — all variables advance in lock-step.
func pitchforkCombos(names []string, valueSets [][]string) []map[string]string {
	// Length = minimum of all value lists
	minLen := len(valueSets[0])
	for _, vs := range valueSets[1:] {
		if len(vs) < minLen {
			minLen = len(vs)
		}
	}

	combos := make([]map[string]string, 0, minLen)
	for i := 0; i < minLen; i++ {
		combo := make(map[string]string, len(names))
		for j, name := range names {
			combo[name] = valueSets[j][i]
		}
		combos = append(combos, combo)
	}
	return combos
}

// clusterbombCombos: cartesian product of all variable values.
func clusterbombCombos(names []string, valueSets [][]string) []map[string]string {
	// Limit total combos to prevent explosion
	const maxCombos = 10000
	total := 1
	for _, vs := range valueSets {
		total *= len(vs)
		if total > maxCombos {
			total = maxCombos
			break
		}
	}

	combos := make([]map[string]string, 0, total)
	indices := make([]int, len(names))

	for count := 0; count < total; count++ {
		combo := make(map[string]string, len(names))
		for j, name := range names {
			combo[name] = valueSets[j][indices[j]]
		}
		combos = append(combos, combo)

		// Increment indices (like a counter)
		for j := len(indices) - 1; j >= 0; j-- {
			indices[j]++
			if indices[j] < len(valueSets[j]) {
				break
			}
			indices[j] = 0
		}
	}
	return combos
}

// dedup removes duplicate combinations.
func dedup(combos []map[string]string) []map[string]string {
	seen := make(map[string]bool)
	var result []map[string]string
	for _, combo := range combos {
		key := fmt.Sprintf("%v", combo)
		if !seen[key] {
			seen[key] = true
			result = append(result, combo)
		}
	}
	return result
}

// templateNeedsOOB checks whether the template references any OOB variables
// or has OOB-related matchers, so we know to generate OOB domains.
func templateNeedsOOB(t *tpl.PocTemplate) bool {
	// Check all requests for OOB directive
	for _, req := range t.Requests {
		if req.OOB != "" {
			return true
		}
		for _, m := range req.Matchers {
			if strings.Contains(strings.ToLower(m), "oob_received") {
				return true
			}
		}
	}

	// Check if any part of the template references {{oob_domain}}, {{oob_url}}, {{oob_host}}
	check := func(s string) bool {
		lower := strings.ToLower(s)
		return strings.Contains(lower, "{{oob_domain}}") ||
			strings.Contains(lower, "{{oob_url}}") ||
			strings.Contains(lower, "{{oob_host}}")
	}

	for _, req := range t.Requests {
		if check(req.Path) || check(req.Body) {
			return true
		}
		for _, v := range req.Headers {
			if check(v) {
				return true
			}
		}
	}

	for _, v := range t.Variables {
		if check(v) {
			return true
		}
	}

	return false
}

// runOnce executes the template once with current variable values.
func (r *Runner) runOnce(t *tpl.PocTemplate, target string) *tpl.ScanResult {
	result := &tpl.ScanResult{
		Target:       target,
		TemplateID:   t.Metadata.ID,
		TemplateName: t.Metadata.Name,
		TemplatePath: t.Path,
		Severity:     t.Metadata.Severity,
		CVE:          t.Metadata.CVE,
		Tags:         append([]string(nil), t.Metadata.Tags...),
		Extracted:    make(map[string]string),
		Author:       t.Metadata.Author,
		Description:  t.Metadata.Description,
		Affects:      t.Metadata.Affects,
		References:   append([]string(nil), t.Metadata.References...),
		CVSSScore:    t.Metadata.CVSSScore,
		ShodanQuery:  t.Metadata.ShodanQuery,
		FofaQuery:    t.Metadata.FofaQuery,
	}
	if result.TemplateName == "" {
		result.TemplateName = t.Path
	}
	if len(t.Requests) == 0 {
		result.Error = "template has no requests"
		if r.opts.Verbose {
			output.PrintVerboseError(result.TemplateName, target, result.Error)
		}
		return result
	}

	// ── OOB Setup ──────────────────────────────────────────────────────────
	// Automatically detect whether this template needs OOB and generate
	// a unique token per execution. No user flags needed.
	var oobToken string
	needsOOB := templateNeedsOOB(t)
	oobAvailable := r.opts.OOBManager != nil && r.opts.OOBManager.Available()

	var oobDomain string
	if needsOOB && oobAvailable {
		oobToken = r.opts.OOBManager.GenerateToken()
		oobDomain = r.opts.OOBManager.Domain(oobToken)
	}

	res := resolver.New(target, t.Variables, oobDomain)
	extractedAll := make(map[string]string)
	lastURL := target
	var lastResp *httpclient.Response
	var interactions []tpl.RequestResponse

	for i := range t.Requests {
		req := &t.Requests[i]
		res.AddVars(extractedAll)

		resp, rawReq, curlCmd, err := r.sendRequest(req, target, res)
		if err != nil {
			result.Error = err.Error()
			if r.opts.Verbose {
				errMsg := err.Error()
				if strings.Contains(errMsg, "context deadline exceeded") ||
					strings.Contains(errMsg, "timeout") {
					output.PrintVerboseSkip(target, "request timeout")
				} else {
					output.PrintVerboseError(result.TemplateName, target, errMsg)
				}
			}
			return result
		}
		lastURL = resp.FinalURL
		lastResp = resp

		// Capture request/response pair
		interactions = append(interactions, tpl.RequestResponse{
			Request:     rawReq,
			Response:    buildRawResponse(resp.StatusCode, resp.Headers, resp.Body),
			CURLCommand: curlCmd,
		})

		if r.opts.Verbose {
			output.PrintVerboseResponse(resp.StatusCode, resp.FinalURL, len(resp.Body), resp.Elapsed.Seconds())
		}

		// Run extractors
		extracted := r.runExtractors(req, resp)
		for k, v := range extracted {
			extractedAll[k] = v
		}

		// Evaluate matchers
		if len(req.Matchers) > 0 {
			// ── OOB Polling ─────────────────────────────────────────────
			oobHit := false
			if needsOOB && oobAvailable && oobToken != "" && req.OOB != "" {
				if r.opts.Verbose {
					output.PrintVerboseOOBPoll(r.opts.OOBManager.ProviderName(), oobToken)
				}
				oobHit = r.opts.OOBManager.Poll(oobToken, 68*time.Second)
				if r.opts.Verbose {
					output.PrintVerboseOOBResult(oobHit)
				}
			}

			ctx := matcher.NewResponseCtx(
				resp.StatusCode,
				resp.Headers,
				resp.Body,
				resp.FinalURL,
				oobHit,
			)
			matched, evalErr := matcher.EvaluateAll(req.Matchers, req.Condition, ctx)
			if r.opts.Verbose {
				if evalErr != nil {
					output.PrintVerboseError(result.TemplateName, target, "matcher eval: "+evalErr.Error())
				}
				output.PrintVerboseMatch(req.Condition, matched && evalErr == nil)
			}
			_ = evalErr
			if !matched {
				if r.opts.Verbose {
					output.PrintVerboseMiss(result.TemplateName, target)
				}
				return result
			}
		}
	}

	result.Vulnerable = true
	result.MatchedAt = lastURL
	result.Interactions = interactions

	internalNames := r.internalExtractorNames(t)
	for k, v := range extractedAll {
		if !internalNames[k] {
			result.Extracted[k] = v
		}
	}

	// If no extractors produced evidence, auto-extract evidence from matchers
	if len(result.Extracted) == 0 && lastResp != nil {
		for k, v := range r.collectMatcherEvidence(t.Requests, lastResp) {
			result.Extracted[k] = v
		}
	}

	if r.opts.Verbose {
		// Print compact single-line result (same format as non-verbose)
		output.PrintResult(result, true)
	}

	return result
}

// collectMatcherEvidence extracts proof strings from the response body
// based on what the matchers were looking for.
func (r *Runner) collectMatcherEvidence(reqs []tpl.HttpRequest, resp *httpclient.Response) map[string]string {
	evidence := make(map[string]string)

	for _, req := range reqs {
		for _, expr := range req.Matchers {
			expr = strings.TrimSpace(expr)

			// status_code == 200  →  show actual status
			if strings.Contains(strings.ToLower(expr), "status_code") ||
				strings.Contains(strings.ToLower(expr), "status") {
				evidence["status"] = strconv.Itoa(resp.StatusCode)
				continue
			}

			// oob_received == true  →  show OOB hit
			if strings.Contains(strings.ToLower(expr), "oob_received") {
				evidence["oob"] = "callback received"
				continue
			}

			// body contains "literal"  →  find and show the literal in context
			if m := reContains.FindStringSubmatch(expr); m != nil {
				needle := m[1]
				if snippet := bodySnippet(resp.Body, needle, 60); snippet != "" {
					evidence["match"] = snippet
				}
				continue
			}

			// body matches /regex/  →  extract the matching text
			if m := reMatches.FindStringSubmatch(expr); m != nil {
				pattern := m[1]
				re, err := regexp.Compile("(?is)" + pattern)
				if err != nil {
					continue
				}
				found := re.FindString(resp.Body)
				if found != "" {
					snip := strings.TrimSpace(found)
					if len(snip) > 80 {
						snip = snip[:80] + "…"
					}
					evidence["match"] = snip
				}
				continue
			}
		}
	}

	// Deduplicate: if status already covered by a richer match, drop it
	if len(evidence) > 1 {
		delete(evidence, "status")
	}

	return evidence
}

// reContains matches:  body contains "text"  or  body contains 'text'
var reContains = regexp.MustCompile(`(?i)body\s+contains\s+["'](.+?)["']`)

// reMatches matches:  body matches /pattern/
var reMatches = regexp.MustCompile(`(?i)body\s+matches\s+/(.+?)/`)

// bodySnippet returns up to maxLen chars of body context around needle.
func bodySnippet(body, needle string, maxLen int) string {
	lower := strings.ToLower(body)
	idx := strings.Index(lower, strings.ToLower(needle))
	if idx < 0 {
		return ""
	}
	start := idx - 10
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + 10
	if end > len(body) {
		end = len(body)
	}
	snip := strings.TrimSpace(body[start:end])
	snip = strings.ReplaceAll(snip, "\n", " ")
	snip = strings.ReplaceAll(snip, "\r", "")
	if len(snip) > maxLen {
		snip = snip[:maxLen] + "…"
	}
	return fmt.Sprintf("%s", snip)
}

// ── Internals ─────────────────────────────────────────────────────────────────

func (r *Runner) sendRequest(req *tpl.HttpRequest, target string, res *resolver.Resolver) (*httpclient.Response, string, string, error) {
	path := res.Resolve(req.Path)

	var rawURL string
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		rawURL = path
	} else {
		parsed, err := url.Parse(target)
		if err != nil {
			return nil, "", "", err
		}
		base := parsed.Scheme + "://" + parsed.Host
		rawURL = base + "/" + strings.TrimPrefix(path, "/")
	}

	headers := res.ResolveMap(req.Headers)
	body := res.Resolve(req.Body)

	if r.opts.Verbose {
		output.PrintVerboseRequest(req.Method, rawURL, headers, body)
	}

	r.client.FollowRedirects = req.FollowRedirects
	r.client.Timeout = time.Duration(req.Timeout) * time.Second

	// Build raw request string and curl command for the report
	rawReq := buildRawRequest(req.Method, rawURL, headers, body)
	curlCmd := buildCURLCommand(req.Method, rawURL, headers, body)

	resp, err := r.client.Do(req.Method, rawURL, headers, body)
	return resp, rawReq, curlCmd, err
}

// buildRawRequest reconstructs a raw HTTP request string for display.
func buildRawRequest(method, rawURL string, headers map[string]string, body string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Sprintf("%s %s HTTP/1.1\n", method, rawURL)
	}

	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", parsed.Host))
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}

// buildRawResponse reconstructs a raw HTTP response string for display.
func buildRawResponse(statusCode int, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText(statusCode)))
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

func statusText(code int) string {
	texts := map[int]string{
		200: "OK", 201: "Created", 204: "No Content",
		301: "Moved Permanently", 302: "Found", 304: "Not Modified",
		400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
		404: "Not Found", 405: "Method Not Allowed",
		500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
	}
	if t, ok := texts[code]; ok {
		return t
	}
	return "Unknown"
}

// buildCURLCommand builds a curl command string to reproduce the request.
func buildCURLCommand(method, rawURL string, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("curl -k -X %s '%s'", method, rawURL))
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf(" -H '%s: %s'", k, v))
	}
	if body != "" {
		escaped := strings.ReplaceAll(body, "'", "'\\''")
		sb.WriteString(fmt.Sprintf(" -d '%s'", escaped))
	}
	return sb.String()
}

func (r *Runner) runExtractors(req *tpl.HttpRequest, resp *httpclient.Response) map[string]string {
	out := make(map[string]string)
	for _, ext := range req.Extractors {
		val := r.extractor.Extract(ext, resp.StatusCode, resp.Headers, resp.Body, resp.FinalURL)
		if val != "" {
			out[ext.Name] = val
			if r.opts.Verbose && !ext.Internal {
				output.PrintVerboseExtracted(ext.Name, val)
			}
		}
	}
	return out
}

func (r *Runner) internalExtractorNames(t *tpl.PocTemplate) map[string]bool {
	m := make(map[string]bool)
	for _, req := range t.Requests {
		for _, ext := range req.Extractors {
			if ext.Internal {
				m[ext.Name] = true
			}
		}
	}
	return m
}