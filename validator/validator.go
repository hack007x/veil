// Package validator performs two-pass static analysis on .poc templates.
//
// Pass 1 — Raw-text lint:
//   Scans the original file content line-by-line to catch every mistake the
//   parser silently swallows: typo'd prefixes (@ vs #@), missing spaces after
//   ## / #@ / #> / #$, unknown directive keys, directives written before any
//   request block, invalid directive values, malformed extractor syntax, and
//   more.
//
// Pass 2 — AST validation:
//   Validates the parsed data structure: metadata fields, variable names,
//   HTTP method names, matcher expressions, extractor fields, placeholder
//   resolution, and cross-request consistency.
//
// Always call ValidateRaw (not Validate) so that Pass 1 runs.
package validator

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	tpl "github.com/hack007x/veil/template"
)

// ─── Issue / Report ───────────────────────────────────────────────────────────

// Severity classifies a validation issue.
type Severity string

const (
	SevError   Severity = "ERROR"
	SevWarning Severity = "WARNING"
	SevInfo    Severity = "INFO"
)

// Issue is one validation finding.
type Issue struct {
	Severity Severity
	Line     int    // 0 = not line-specific
	Field    string // location hint
	Message  string
}

// Report is the complete validation result for one template.
type Report struct {
	Path     string
	Issues   []Issue
	HasError bool
}

func (r *Report) add(sev Severity, line int, field, msg string) {
	r.Issues = append(r.Issues, Issue{sev, line, field, msg})
	if sev == SevError {
		r.HasError = true
	}
}
func (r *Report) errorf(line int, field, f string, a ...interface{}) {
	r.add(SevError, line, field, fmt.Sprintf(f, a...))
}
func (r *Report) warnf(line int, field, f string, a ...interface{}) {
	r.add(SevWarning, line, field, fmt.Sprintf(f, a...))
}
func (r *Report) infof(line int, field, f string, a ...interface{}) {
	r.add(SevInfo, line, field, fmt.Sprintf(f, a...))
}

// ─── Entry points ─────────────────────────────────────────────────────────────

// ValidateRaw runs both Pass 1 (raw-text lint) and Pass 2 (AST).
// rawContent is the original .poc file bytes (before parsing).
// This is the preferred entry point — always use it when you have the source.
func ValidateRaw(t *tpl.PocTemplate, rawContent string) *Report {
	r := &Report{Path: t.Path}
	rawLint(r, rawContent)
	astValidate(r, t)
	return r
}

// Validate runs only Pass 2 (AST). Use when raw content is unavailable.
func Validate(t *tpl.PocTemplate) *Report {
	r := &Report{Path: t.Path}
	astValidate(r, t)
	return r
}

// ═══════════════════════════════════════════════════════════════════════════════
// PASS 1 — Raw text lint
// ═══════════════════════════════════════════════════════════════════════════════

// lintState mirrors the parser's internal FSM so we always know our context.
type lintState int

const (
	lsPre        lintState = iota // before any HTTP request line
	lsHeaders                     // inside request-header section
	lsBody                        // inside request body
	lsDirectives                  // after first #@ / #>
)

// knownHTTPMethods are all methods the parser recognises (must be uppercase).
var knownHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
	"CONNECT": true,
}

// knownMetaKeys are the keys the parser recognises after "## ".
var knownMetaKeys = map[string]bool{
	"id": true, "name": true, "author": true, "severity": true, "cve": true,
	"tags": true, "description": true, "reference": true, "references": true,
	"affects": true, "cvss-score": true, "shodan-query": true,
	"fofa-query": true, "verification": true,
}

// knownDirectiveKeys are the keys parseDirective recognises after "#@ ".
var knownDirectiveKeys = map[string]bool{
	"matcher": true, "condition": true, "follow_redirects": true,
	"timeout": true, "oob": true, "attack": true,
}

// knownExtractParams are the KV keys parseExtractor recognises.
var knownExtractParams = map[string]bool{
	"name": true, "from": true, "internal": true, "group": true,
	"regex": true, "json": true, "xpath": true, "kval": true,
}

// extractMethodParams are the keys that specify an extraction method.
var extractMethodParams = []string{"regex", "json", "xpath", "kval"}

var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}
var validOOBTypes   = map[string]bool{"dns": true, "http": true}
var validConditions = map[string]bool{"and": true, "or": true}
var validAttackModes = map[string]bool{"sniper": true, "pitchfork": true, "clusterbomb": true}

func rawLint(r *Report, content string) {
	// Normalise line endings
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	allLines := strings.Split(content, "\n")
	blockLines := []string{}
	baseLineNo := 1

	flush := func() {
		if len(blockLines) > 0 {
			lintBlock(r, blockLines, baseLineNo)
		}
	}

	for i, line := range allLines {
		if strings.TrimSpace(line) == "---" {
			flush()
			blockLines = nil
			baseLineNo = i + 2
		} else {
			blockLines = append(blockLines, line)
		}
	}
	flush()
}

func lintBlock(r *Report, lines []string, base int) {
	state := lsPre
	hasRequest := false

	for i, rawLine := range lines {
		lineNo := base + i
		stripped := strings.TrimSpace(rawLine)

		// ── 1. Typo / malformed prefix detection ─────────────────────────────
		//    These are checked before anything else, on every line.

		// "@" without leading "#" — almost certainly "@ key: val" instead of "#@ key: val"
		if strings.HasPrefix(stripped, "@ ") {
			colon := strings.Index(stripped, ":")
			if colon > 0 {
				r.errorf(lineNo, "syntax",
					"directive prefix '@' is missing '#': %q  →  did you mean '#@ %s'?",
					stripped, stripped[2:])
			}
		}

		// "#@key:" — no space after "#@"
		if len(stripped) >= 3 && stripped[:2] == "#@" && stripped[2] != ' ' {
			r.errorf(lineNo, "syntax",
				"'#@' must be followed by a space: %q  →  did you mean '#@ %s'?",
				stripped, stripped[2:])
		}

		// "#>key:" — no space after "#>"
		if len(stripped) >= 3 && stripped[:2] == "#>" && stripped[2] != ' ' {
			r.errorf(lineNo, "syntax",
				"'#>' must be followed by a space: %q  →  did you mean '#> %s'?",
				stripped, stripped[2:])
		}

		// "##key:" — no space after "##"
		if len(stripped) >= 3 && stripped[:2] == "##" && stripped[2] != ' ' {
			r.errorf(lineNo, "syntax",
				"'##' must be followed by a space: %q  →  did you mean '## %s'?",
				stripped, stripped[2:])
		}

		// "#$key=" — no space after "#$"
		if len(stripped) >= 3 && stripped[:2] == "#$" && stripped[2] != ' ' {
			r.errorf(lineNo, "syntax",
				"'#$' must be followed by a space: %q  →  did you mean '#$ %s'?",
				stripped, stripped[2:])
		}

		// "# name: foo" — single "#" used where "## " was intended
		if strings.HasPrefix(stripped, "# ") {
			rest := stripped[2:]
			if ci := strings.Index(rest, ":"); ci > 0 {
				key := strings.ToLower(strings.TrimSpace(rest[:ci]))
				if knownMetaKeys[key] {
					r.errorf(lineNo, "syntax",
						"metadata prefix should be '## ' (two hashes): %q  →  did you mean '## %s'?",
						stripped, rest)
				}
			}
		}

		// "> extract:" — missing "#"
		if strings.HasPrefix(stripped, "> ") && strings.Contains(strings.ToLower(stripped), "extract:") {
			r.errorf(lineNo, "syntax",
				"extractor prefix is missing '#': %q  →  did you mean '#> %s'?",
				stripped, stripped[2:])
		}

		// "$ name = val" — missing "#"
		if strings.HasPrefix(stripped, "$ ") && strings.Contains(stripped, "=") {
			r.errorf(lineNo, "syntax",
				"variable prefix is missing '#': %q  →  did you mean '#$ %s'?",
				stripped, stripped[2:])
		}

		// ── 2. Classify ───────────────────────────────────────────────────────

		isMeta      := strings.HasPrefix(stripped, "## ")
		isVar       := strings.HasPrefix(stripped, "#$ ")
		isMatcher   := strings.HasPrefix(stripped, "#@ ")
		isExtractor := strings.HasPrefix(stripped, "#> ")
		isComment   := len(stripped) > 1 && stripped[0] == '#' &&
			stripped[1] != '#' && stripped[1] != '@' &&
			stripped[1] != '$' && stripped[1] != '>'
		isEmpty := stripped == ""

		if isComment || stripped == "#" {
			continue
		}

		// ── 3. FSM — mirrors parser.go exactly ────────────────────────────────

		switch state {
		case lsPre:
			switch {
			case isMeta:
				lintMetaLine(r, lineNo, stripped[3:])
			case isVar:
				lintVarLine(r, lineNo, stripped[3:])
			case isMatcher:
				// parser.go: "directives before any request — ignore"
				r.errorf(lineNo, "structure",
					"'#@ ...' appears before any HTTP request line and will be silently ignored by the parser")
			case isExtractor:
				r.errorf(lineNo, "structure",
					"'#> ...' appears before any HTTP request line and will be silently ignored by the parser")
			case isEmpty:
				// blank line in pre-request section — harmless
			default:
				// Should be an HTTP request line
				parts := strings.Fields(stripped)
				if len(parts) >= 2 {
					upperMethod := strings.ToUpper(parts[0])
					if knownHTTPMethods[upperMethod] {
						// Valid request line
						if parts[0] != upperMethod {
							r.errorf(lineNo, "request.method",
								"HTTP method must be UPPERCASE: %q  →  did you mean %q?",
								parts[0], upperMethod)
						}
						hasRequest = true
						state = lsHeaders
						if strings.TrimSpace(parts[1]) == "" {
							r.errorf(lineNo, "request.path", "request path is empty")
						}
					} else {
						// Not a valid method — typo or unknown content
						lintUnknownPreLine(r, lineNo, stripped)
					}
				} else {
					lintUnknownPreLine(r, lineNo, stripped)
				}
			}

		case lsHeaders:
			switch {
			case isEmpty:
				state = lsBody
			case isMatcher:
				state = lsDirectives
				lintDirectiveLine(r, lineNo, stripped[3:])
			case isExtractor:
				state = lsDirectives
				lintExtractorLine(r, lineNo, stripped[3:])
			case isVar:
				lintVarLine(r, lineNo, stripped[3:])
			case isMeta:
				lintMetaLine(r, lineNo, stripped[3:])
			default:
				lintHeaderLine(r, lineNo, stripped)
			}

		case lsBody:
			switch {
			case isMatcher:
				state = lsDirectives
				lintDirectiveLine(r, lineNo, stripped[3:])
			case isExtractor:
				state = lsDirectives
				lintExtractorLine(r, lineNo, stripped[3:])
			default:
				// Body content — check for forgotten directive prefixes inside body
				lintBodyLine(r, lineNo, stripped)
			}

		case lsDirectives:
			switch {
			case isMatcher:
				lintDirectiveLine(r, lineNo, stripped[3:])
			case isExtractor:
				lintExtractorLine(r, lineNo, stripped[3:])
			case isVar:
				lintVarLine(r, lineNo, stripped[3:])
			case isMeta:
				lintMetaLine(r, lineNo, stripped[3:])
			case isEmpty:
				// fine
			default:
				// Parser silently ignores these — we surface them
				r.warnf(lineNo, "structure",
					"unrecognised line in directive section: %q — will be silently ignored by the parser",
					stripped)
			}
		}
	}

	// Warn if the block had non-trivial content but no request was parsed
	if !hasRequest {
		for _, line := range lines {
			s := strings.TrimSpace(line)
			if s == "" || s == "#" || strings.HasPrefix(s, "# ") {
				continue
			}
			// Has something meaningful (not just comments)
			r.errorf(base, "structure",
				"block has content but no valid HTTP request line — nothing in this block will be executed")
			break
		}
	}
}

// ── Line-level lint helpers ────────────────────────────────────────────────────

func lintMetaLine(r *Report, lineNo int, after string) {
	ci := strings.Index(after, ":")
	if ci < 0 {
		r.errorf(lineNo, "metadata",
			"metadata line missing ':' separator: %q  →  expected '## key: value'", "## "+after)
		return
	}
	key := strings.ToLower(strings.TrimSpace(after[:ci]))
	val := strings.TrimSpace(after[ci+1:])

	if !knownMetaKeys[key] {
		r.errorf(lineNo, "metadata",
			"unknown metadata key %q — valid keys: id, name, author, severity, cve, tags, description, affects, reference, references, cvss-score, shodan-query, fofa-query, verification",
			key)
		return
	}
	if val == "" {
		r.warnf(lineNo, "metadata."+key, "metadata field %q has an empty value", key)
	}
	switch key {
	case "severity":
		if !validSeverities[strings.ToLower(val)] {
			r.errorf(lineNo, "metadata.severity",
				"invalid severity %q — must be one of: critical, high, medium, low, info", val)
		}
	case "cve":
		if val != "" && !cveRe.MatchString(val) {
			r.warnf(lineNo, "metadata.cve",
				"CVE %q does not match expected format CVE-YYYY-NNNNN", val)
		}
	case "cvss-score":
		if val != "" {
			if score, err := strconv.ParseFloat(val, 64); err != nil {
				r.errorf(lineNo, "metadata.cvss-score",
					"CVSS score %q is not a valid number", val)
			} else if score < 0 || score > 10 {
				r.errorf(lineNo, "metadata.cvss-score",
					"CVSS score %q out of range — must be 0.0 to 10.0", val)
			}
		}
	case "verification":
		if val != "" && val != "true" && val != "false" {
			r.errorf(lineNo, "metadata.verification",
				"verification %q must be 'true' or 'false'", val)
		}
	}
}

func lintVarLine(r *Report, lineNo int, after string) {
	ei := strings.Index(after, "=")
	if ei < 0 {
		r.errorf(lineNo, "variable",
			"variable definition missing '=': %q  →  expected '#$ name = value'", "#$ "+after)
		return
	}
	name := strings.TrimSpace(after[:ei])
	if name == "" {
		r.errorf(lineNo, "variable", "variable name is empty in: %q", "#$ "+after)
		return
	}
	if !identRe.MatchString(name) {
		r.errorf(lineNo, "variable",
			"variable name %q is not a valid identifier (must match [A-Za-z_][A-Za-z0-9_]*)", name)
	}
}

func lintHeaderLine(r *Report, lineNo int, stripped string) {
	ci := strings.Index(stripped, ":")
	if ci <= 0 {
		r.errorf(lineNo, "request.header",
			"malformed header (no ':' separator): %q  →  expected 'Header-Name: value'", stripped)
		return
	}
	key := strings.TrimSpace(stripped[:ci])
	if key == "" {
		r.errorf(lineNo, "request.header", "header name is empty in line: %q", stripped)
	}
	// Accidental second request line placed in header section
	if knownHTTPMethods[strings.ToUpper(key)] {
		r.warnf(lineNo, "request.header",
			"line %q looks like an HTTP request line inside the header section — did you forget a blank line or '---' separator?",
			stripped)
	}
}

func lintDirectiveLine(r *Report, lineNo int, after string) {
	ci := strings.Index(after, ":")
	if ci < 0 {
		r.errorf(lineNo, "directive",
			"'#@ ...' directive missing ':' separator: %q  →  expected '#@ key: value'", "#@ "+after)
		return
	}
	key := strings.ToLower(strings.TrimSpace(after[:ci]))
	val := strings.TrimSpace(after[ci+1:])

	if !knownDirectiveKeys[key] {
		r.errorf(lineNo, "directive",
			"unknown directive key %q — valid keys: matcher, condition, follow_redirects, timeout, oob",
			key)
		return
	}

	switch key {
	case "matcher":
		if val == "" {
			r.errorf(lineNo, "directive.matcher",
				"'#@ matcher:' value is empty — a matcher expression is required")
			return
		}
		for _, e := range validateMatcherExpr(val) {
			r.errorf(lineNo, "directive.matcher", "%s", e)
		}

	case "condition":
		if val == "" {
			r.errorf(lineNo, "directive.condition",
				"'#@ condition:' value is empty — must be 'and' or 'or'")
			return
		}
		if !validConditions[strings.ToLower(val)] {
			r.errorf(lineNo, "directive.condition",
				"invalid condition %q — must be 'and' or 'or'", val)
		}

	case "follow_redirects":
		lower := strings.ToLower(val)
		if lower != "true" && lower != "false" && lower != "1" && lower != "0" && lower != "yes" && lower != "no" {
			r.errorf(lineNo, "directive.follow_redirects",
				"invalid value %q — must be: true / false / 1 / 0 / yes / no", val)
		}

	case "timeout":
		if val == "" {
			r.errorf(lineNo, "directive.timeout", "'#@ timeout:' value is empty — specify a number of seconds")
			return
		}
		n, err := strconv.Atoi(val)
		if err != nil {
			r.errorf(lineNo, "directive.timeout",
				"timeout value %q is not an integer: %v", val, err)
		} else if n < 0 {
			r.errorf(lineNo, "directive.timeout", "timeout must be >= 0, got %d", n)
		} else if n > 300 {
			r.warnf(lineNo, "directive.timeout",
				"timeout %d seconds is very large (max recommended: 300)", n)
		}

	case "oob":
		if val == "" {
			r.errorf(lineNo, "directive.oob", "'#@ oob:' value is empty — must be 'dns' or 'http'")
			return
		}
		if !validOOBTypes[strings.ToLower(val)] {
			r.errorf(lineNo, "directive.oob",
				"invalid oob type %q — must be 'dns' or 'http'", val)
		}

	case "attack":
		if val == "" {
			r.errorf(lineNo, "directive.attack", "'#@ attack:' value is empty — must be 'sniper', 'pitchfork', or 'clusterbomb'")
			return
		}
		if !validAttackModes[strings.ToLower(val)] {
			r.errorf(lineNo, "directive.attack",
				"invalid attack mode %q — must be 'sniper', 'pitchfork', or 'clusterbomb'", val)
		}
	}
}

func lintExtractorLine(r *Report, lineNo int, after string) {
	ci := strings.Index(after, ":")
	if ci < 0 {
		r.errorf(lineNo, "extractor",
			"'#> ...' missing ':' separator: %q  →  expected '#> extract: name=X, ...'", "#> "+after)
		return
	}
	key := strings.ToLower(strings.TrimSpace(after[:ci]))
	if key != "extract" {
		r.errorf(lineNo, "extractor",
			"'#>' directive key must be 'extract', got %q", key)
		return
	}

	kv := parseRawKV(after[ci+1:])

	// name is required
	name := strings.TrimSpace(kv["name"])
	if name == "" {
		r.errorf(lineNo, "extractor.name",
			"extractor missing required 'name=' parameter  →  e.g. '#> extract: name=token, regex=/pattern/'")
	} else if !identRe.MatchString(name) {
		r.errorf(lineNo, "extractor.name",
			"extractor name %q is not a valid identifier", name)
	}

	// At least one method key must be present and non-empty
	methodCount := 0
	for _, mk := range extractMethodParams {
		if v, ok := kv[mk]; ok && strings.TrimSpace(v) != "" {
			methodCount++
		}
	}
	if methodCount == 0 {
		r.errorf(lineNo, "extractor.method",
			"extractor has no extraction method — add one of: regex=/pattern/, json=$.path, kval=key, xpath=//path")
	}
	if methodCount > 1 {
		r.warnf(lineNo, "extractor.method",
			"multiple extraction methods specified — only the first matching (regex > json > xpath > kval) will be used")
	}

	// Validate regex pattern
	if pat := strings.TrimSpace(kv["regex"]); pat != "" {
		if _, err := regexp.Compile("(?is)" + pat); err != nil {
			r.errorf(lineNo, "extractor.regex", "invalid regex pattern %q: %v", pat, err)
		}
	}

	// Validate group
	if gStr, ok := kv["group"]; ok {
		gStr = strings.TrimSpace(gStr)
		if gStr == "" {
			r.errorf(lineNo, "extractor.group", "'group=' value is empty — must be an integer >= 0")
		} else if g, err := strconv.Atoi(gStr); err != nil {
			r.errorf(lineNo, "extractor.group", "'group=%s' is not an integer: %v", gStr, err)
		} else if g < 0 {
			r.errorf(lineNo, "extractor.group", "group must be >= 0, got %d", g)
		}
	}

	// Validate from
	if src, ok := kv["from"]; ok {
		src = strings.TrimSpace(src)
		if src != "" {
			lintExtractFrom(r, lineNo, src)
		}
	}

	// Validate internal
	if iv, ok := kv["internal"]; ok {
		lower := strings.ToLower(strings.TrimSpace(iv))
		if lower != "true" && lower != "false" && lower != "1" && lower != "0" {
			r.errorf(lineNo, "extractor.internal",
				"'internal=%s' must be true/false/1/0", iv)
		}
	}

	// Warn about unknown keys
	for k := range kv {
		if !knownExtractParams[k] {
			r.warnf(lineNo, "extractor",
				"unknown extractor parameter %q — valid: name, from, regex, json, xpath, kval, group, internal", k)
		}
	}
}

var validExtractFromSimple = map[string]bool{
	"body": true, "url": true, "status_code": true,
	"status": true, "header": true, "headers": true,
}
var extractFromBracketRe = regexp.MustCompile(`(?i)^headers?\[[\'\"](.+?)[\'\"]\]$`)
var extractFromDotRe     = regexp.MustCompile(`(?i)^headers?\.(.+)$`)

func lintExtractFrom(r *Report, lineNo int, src string) {
	lower := strings.ToLower(src)
	if validExtractFromSimple[lower] ||
		extractFromBracketRe.MatchString(lower) ||
		extractFromDotRe.MatchString(lower) {
		return
	}
	r.errorf(lineNo, "extractor.from",
		"invalid 'from' source %q — valid: body, url, status_code, headers, header[\"Name\"], headers.name", src)
}

func lintBodyLine(r *Report, lineNo int, stripped string) {
	// "@ key: val" or "> extract:" inside body = forgotten "#"
	if strings.HasPrefix(stripped, "@ ") {
		if strings.Contains(stripped, ":") {
			r.errorf(lineNo, "body",
				"found '@ ...' inside request body — missing '#': %q  →  did you mean '#@ %s'?",
				stripped, stripped[2:])
		}
	}
	if strings.HasPrefix(stripped, "> ") && strings.Contains(strings.ToLower(stripped), "extract:") {
		r.errorf(lineNo, "body",
			"found '> ...' inside request body — missing '#': %q  →  did you mean '#> %s'?",
			stripped, stripped[2:])
	}
}

func lintUnknownPreLine(r *Report, lineNo int, stripped string) {
	parts := strings.Fields(stripped)
	if len(parts) >= 2 {
		upper := strings.ToUpper(parts[0])
		// Lowercase HTTP method
		if knownHTTPMethods[upper] {
			r.errorf(lineNo, "request.method",
				"HTTP method must be uppercase: %q  →  did you mean %q?", parts[0], upper)
			return
		}
	}
	// Line with ":" that isn't a header (no request yet) — probably metadata typo
	if strings.Contains(stripped, ":") {
		r.warnf(lineNo, "structure",
			"unrecognised line before any HTTP request: %q — will be silently ignored", stripped)
	}
}

// parseRawKV is the same KV parser as parser.go's parseKV — used in raw linting.
func parseRawKV(s string) map[string]string {
	result := make(map[string]string)
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			break
		}
		ks := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' && s[i] != '\t' && s[i] != ',' {
			i++
		}
		key := strings.ToLower(strings.TrimSpace(s[ks:i]))
		if key == "" {
			i++
			continue
		}
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			result[key] = ""
			continue
		}
		i++ // skip '='
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			result[key] = ""
			break
		}
		var val string
		switch s[i] {
		case '/':
			i++
			start := i
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == '/' {
					break
				}
				i++
			}
			val = s[start:i]
			if i < len(s) {
				i++
			}
		case '"', '\'':
			q := s[i]
			i++
			start := i
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == q {
					break
				}
				i++
			}
			val = s[start:i]
			if i < len(s) {
				i++
			}
		default:
			start := i
			for i < len(s) && s[i] != ',' {
				i++
			}
			val = strings.TrimSpace(s[start:i])
		}
		result[key] = val
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// PASS 2 — AST validation
// ═══════════════════════════════════════════════════════════════════════════════

var cveRe   = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)
var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func astValidate(r *Report, t *tpl.PocTemplate) {
	checkASTMetadata(r, t)
	checkASTVariables(r, t)
	checkASTRequests(r, t)
	checkASTCrossRequest(r, t)
}

func checkASTMetadata(r *Report, t *tpl.PocTemplate) {
	m := t.Metadata

	// ── Required fields (ERROR if missing) ────────────────────────────────
	if strings.TrimSpace(m.ID) == "" {
		r.errorf(0, "metadata.id", "required field '## id:' is missing — every template must have a unique identifier")
	}
	if strings.TrimSpace(m.Name) == "" {
		r.errorf(0, "metadata.name", "required field '## name:' is missing — every template must have a descriptive name")
	}
	if strings.TrimSpace(m.Author) == "" {
		r.errorf(0, "metadata.author", "required field '## author:' is missing — every template must declare its author")
	}
	sev := strings.ToLower(strings.TrimSpace(m.Severity))
	if sev == "" {
		r.errorf(0, "metadata.severity", "required field '## severity:' is missing — must be: critical, high, medium, low, info")
	} else if !validSeverities[sev] {
		r.errorf(0, "metadata.severity",
			"invalid severity %q — must be: critical, high, medium, low, info", m.Severity)
	}

	// ── Optional field validation ─────────────────────────────────────────
	if m.CVE != "" && !cveRe.MatchString(m.CVE) {
		r.warnf(0, "metadata.cve", "CVE %q does not match format CVE-YYYY-NNNNN", m.CVE)
	}
	if m.CVSSScore != "" {
		if score, err := strconv.ParseFloat(m.CVSSScore, 64); err != nil {
			r.errorf(0, "metadata.cvss-score", "CVSS score %q is not a valid number", m.CVSSScore)
		} else if score < 0 || score > 10 {
			r.errorf(0, "metadata.cvss-score", "CVSS score %q out of range — must be 0.0 to 10.0", m.CVSSScore)
		}
	}
	if m.Verification != "" && m.Verification != "true" && m.Verification != "false" {
		r.errorf(0, "metadata.verification", "verification %q must be 'true' or 'false'", m.Verification)
	}
}

func checkASTVariables(r *Report, t *tpl.PocTemplate) {
	for name, val := range t.Variables {
		if !identRe.MatchString(name) {
			r.errorf(0, "variable["+name+"]",
				"variable name %q is not a valid identifier", name)
		}
		checkPlaceholdersAST(r, val, "variable["+name+"].value", nil, t)
	}
}

func checkASTRequests(r *Report, t *tpl.PocTemplate) {
	if len(t.Requests) == 0 {
		r.errorf(0, "requests",
			"template has no HTTP request blocks — at least one GET/POST/... is required")
		return
	}
	extracted := map[string]bool{}
	for i := range t.Requests {
		req := &t.Requests[i]
		pf := fmt.Sprintf("request[%d]", i)

		if !knownHTTPMethods[strings.ToUpper(req.Method)] {
			r.errorf(0, pf+".method", "invalid HTTP method %q", req.Method)
		}
		if strings.TrimSpace(req.Path) == "" {
			r.errorf(0, pf+".path", "request path is empty")
		}
		checkPlaceholdersAST(r, req.Path, pf+".path", extracted, t)
		for k, v := range req.Headers {
			checkPlaceholdersAST(r, v, fmt.Sprintf("%s.header[%s]", pf, k), extracted, t)
		}
		if req.Body != "" {
			checkPlaceholdersAST(r, req.Body, pf+".body", extracted, t)
		}

		cond := strings.ToLower(req.Condition)
		if cond != "" && !validConditions[cond] {
			r.errorf(0, pf+".condition", "invalid condition %q — must be 'and' or 'or'", req.Condition)
		}

		oob := strings.ToLower(string(req.OOB))
		oobMatcher := false
		for _, m := range req.Matchers {
			if strings.Contains(strings.ToLower(m), "oob_received") {
				oobMatcher = true
				break
			}
		}
		if oobMatcher && oob == "" {
			r.warnf(0, pf+".oob", "matcher uses 'oob_received' but '#@ oob: dns|http' is not set")
		}

		for j, expr := range req.Matchers {
			field := fmt.Sprintf("%s.matcher[%d]", pf, j)
			if strings.TrimSpace(expr) == "" {
				r.errorf(0, field, "matcher expression is empty")
				continue
			}
			for _, e := range validateMatcherExpr(expr) {
				r.errorf(0, field, "%s", e)
			}
		}

		seen := map[string]bool{}
		for k, ext := range req.Extractors {
			field := fmt.Sprintf("%s.extractor[%d]", pf, k)
			if strings.TrimSpace(ext.Name) == "" {
				r.errorf(0, field, "extractor 'name' is missing")
			} else {
				lname := strings.ToLower(ext.Name)
				if seen[lname] {
					r.warnf(0, field, "duplicate extractor name %q in same request", ext.Name)
				}
				seen[lname] = true
			}
			if ext.Method == "" {
				r.errorf(0, field, "extractor has no method — add regex=, json=, xpath=, or kval=")
			}
			if ext.Pattern == "" {
				r.errorf(0, field, "extractor pattern is empty")
			}
			if ext.Method == tpl.ExtractRegex && ext.Pattern != "" {
				if _, err := regexp.Compile("(?is)" + ext.Pattern); err != nil {
					r.errorf(0, field, "invalid regex %q: %v", ext.Pattern, err)
				}
			}
		}

		for _, ext := range req.Extractors {
			if ext.Name != "" {
				extracted[ext.Name] = true
			}
		}
	}
}

func checkASTCrossRequest(r *Report, t *tpl.PocTemplate) {
	for i, req := range t.Requests {
		if len(req.Matchers) == 0 {
			if len(t.Requests) > 1 {
				r.warnf(0, fmt.Sprintf("request[%d]", i),
					"no matchers — request always passes, may produce false positives in chain")
			} else {
				r.infof(0, "request[0]",
					"no matchers — template always reports vulnerable for any reachable target")
			}
		}
	}
}

// ─── Placeholder validation ───────────────────────────────────────────────────

var placeholderRe = regexp.MustCompile(`\{\{([^{}]+)\}\}`)

var builtinVarNames = map[string]bool{
	"hostname": true, "host": true, "baseurl": true, "rooturl": true,
	"scheme": true, "port": true, "path": true,
	"random_ua": true, "timestamp": true,
	"oob_domain": true, "oob_host": true, "oob_url": true,
}

var builtinFnMin = map[string]int{
	"base64": 1, "base64_decode": 1, "url_encode": 1, "url_decode": 1,
	"md5": 1, "sha1": 1, "sha256": 1, "hex_encode": 1, "hex_decode": 1,
	"to_lower": 1, "to_upper": 1, "trim": 1, "len": 1, "reverse": 1,
	"replace": 3, "concat": 1, "random_str": 0, "random_int": 0,
}
var builtinFnMax = map[string]int{
	"base64": 1, "base64_decode": 1, "url_encode": 1, "url_decode": 1,
	"md5": 1, "sha1": 1, "sha256": 1, "hex_encode": 1, "hex_decode": 1,
	"to_lower": 1, "to_upper": 1, "trim": 1, "len": 1, "reverse": 1,
	"replace": 3, "concat": -1, "random_str": 1, "random_int": 2,
}

func checkPlaceholdersAST(r *Report, text, field string, extracted map[string]bool, t *tpl.PocTemplate) {
	for _, m := range placeholderRe.FindAllStringSubmatch(text, -1) {
		inner := strings.TrimSpace(m[1])
		validateOnePlaceholder(r, inner, field, extracted, t)
	}
}

func validateOnePlaceholder(r *Report, inner, field string, extracted map[string]bool, t *tpl.PocTemplate) {
	// Function call?
	if idx := strings.Index(inner, "("); idx > 0 && strings.HasSuffix(inner, ")") {
		fn := strings.ToLower(inner[:idx])
		raw := inner[idx+1 : len(inner)-1]
		minA, ok := builtinFnMin[fn]
		if !ok {
			r.errorf(0, field,
				"{{%s}} calls unknown function %q — known: %s", inner, fn, knownFnNames())
			return
		}
		args := splitFnArgs(raw)
		maxA := builtinFnMax[fn]
		if len(args) < minA {
			r.errorf(0, field,
				"{{%s}} — %q needs at least %d arg(s), got %d", inner, fn, minA, len(args))
		}
		if maxA >= 0 && len(args) > maxA {
			r.errorf(0, field,
				"{{%s}} — %q accepts at most %d arg(s), got %d", inner, fn, maxA, len(args))
		}
		return
	}
	lower := strings.ToLower(inner)
	if builtinVarNames[lower] {
		return
	}
	if _, ok := t.Variables[inner]; ok {
		return
	}
	for k := range t.Variables {
		if strings.ToLower(k) == lower {
			return
		}
	}
	if extracted != nil && extracted[inner] {
		return
	}
	r.warnf(0, field,
		"{{%s}} cannot be resolved — not a built-in variable, not defined with '#$', not extracted by a prior request",
		inner)
}

func splitFnArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQ := rune(0)
	for _, c := range s {
		switch {
		case inQ != 0:
			cur.WriteRune(c)
			if c == inQ {
				inQ = 0
			}
		case c == '"' || c == '\'':
			inQ = c
			cur.WriteRune(c)
		case c == ',':
			args = append(args, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(c)
		}
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		args = append(args, t)
	}
	return args
}

func knownFnNames() string {
	names := make([]string, 0, len(builtinFnMin))
	for n := range builtinFnMin {
		names = append(names, n)
	}
	return strings.Join(names, ", ")
}

// ─── Matcher expression validation ───────────────────────────────────────────

var allOps = []string{
	"not_contains", "starts_with", "ends_with",
	"contains", "matches",
	"==", "!=", "<=", ">=", "<", ">",
}

var compiledOps []*struct {
	op string
	re *regexp.Regexp
}

func init() {
	for _, o := range allOps {
		var pat string
		if o[0] >= 'a' {
			pat = `(?i)\s+` + regexp.QuoteMeta(o) + `\s+`
		} else {
			pat = `\s*` + regexp.QuoteMeta(o) + `\s*`
		}
		compiledOps = append(compiledOps, &struct {
			op string
			re *regexp.Regexp
		}{o, regexp.MustCompile(pat)})
	}
}

var matcherLHSNames = map[string]bool{
	"status_code": true, "status": true, "body": true,
	"url": true, "oob_received": true,
}
var hdrBracketRe = regexp.MustCompile(`^headers?\[[\'\"](.+?)[\'\"]\]$`)
var hdrDotRe     = regexp.MustCompile(`^headers?\.(.+)$`)

func validateMatcherExpr(expr string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return []string{"matcher expression is empty"}
	}
	if parts := splitLogical(expr, "||"); len(parts) > 1 {
		var errs []string
		for _, p := range parts {
			errs = append(errs, validateMatcherExpr(strings.TrimSpace(p))...)
		}
		return errs
	}
	if parts := splitLogical(expr, "&&"); len(parts) > 1 {
		var errs []string
		for _, p := range parts {
			errs = append(errs, validateMatcherExpr(strings.TrimSpace(p))...)
		}
		return errs
	}
	return validateAtomicMatcher(expr)
}

func validateAtomicMatcher(expr string) []string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") && parenMatches(expr) {
		return validateMatcherExpr(expr[1 : len(expr)-1])
	}
	lower := strings.ToLower(expr)
	if strings.HasPrefix(lower, "not ") {
		return validateMatcherExpr(expr[4:])
	}
	if strings.HasPrefix(expr, "!") && !strings.HasPrefix(expr, "!=") {
		return validateMatcherExpr(expr[1:])
	}

	lhs, op, rhs, err := findOp(expr)
	if err != nil {
		return []string{err.Error()}
	}

	var errs []string
	// LHS check
	lhsKey := strings.ToLower(strings.TrimSpace(lhs))
	if !matcherLHSNames[lhsKey] && !hdrBracketRe.MatchString(lhsKey) && !hdrDotRe.MatchString(lhsKey) {
		errs = append(errs, fmt.Sprintf(
			"unknown LHS %q — valid: status_code, body, url, oob_received, header[\"Name\"], headers.name", lhs))
	}

	rhs = strings.TrimSpace(rhs)
	if rhs == "" {
		errs = append(errs, fmt.Sprintf("missing RHS after operator %q", op))
		return errs
	}

	// oob_received constraints
	if lhsKey == "oob_received" {
		if op != "==" && op != "!=" {
			errs = append(errs, fmt.Sprintf("oob_received only supports == and !=, got %q", op))
		}
		if !strings.EqualFold(rhs, "true") && !strings.EqualFold(rhs, "false") {
			errs = append(errs, fmt.Sprintf("oob_received RHS must be 'true' or 'false', got %q", rhs))
		}
		return errs
	}

	// status_code constraints
	isStatus := lhsKey == "status_code" || lhsKey == "status"
	numOps := map[string]bool{"==": true, "!=": true, "<": true, ">": true, "<=": true, ">=": true}
	strOps  := map[string]bool{"contains": true, "not_contains": true, "starts_with": true, "ends_with": true, "matches": true}
	if isStatus && numOps[op] {
		if _, e := strconv.Atoi(strings.Trim(rhs, `'"`)); e != nil {
			errs = append(errs, fmt.Sprintf("status_code requires integer RHS, got %q", rhs))
		}
	}
	if isStatus && strOps[op] {
		errs = append(errs, fmt.Sprintf("operator %q on status_code (integer) — string operators won't work", op))
	}

	// matches: validate regex
	if op == "matches" {
		pat := rhs
		if strings.HasPrefix(pat, "/") && strings.HasSuffix(pat, "/") && len(pat) >= 2 {
			pat = pat[1 : len(pat)-1]
		}
		if _, e := regexp.Compile("(?is)" + pat); e != nil {
			errs = append(errs, fmt.Sprintf("invalid regex in 'matches': %v", e))
		}
	}

	return errs
}

func findOp(expr string) (lhs, op, rhs string, err error) {
	for _, p := range compiledOps {
		if loc := p.re.FindStringIndex(expr); loc != nil {
			return strings.TrimSpace(expr[:loc[0]]),
				p.op,
				strings.TrimSpace(expr[loc[1]:]),
				nil
		}
	}
	return "", "", "", fmt.Errorf(
		"no valid operator in %q — valid: %s", expr, strings.Join(allOps, " "))
}

func splitLogical(expr, op string) []string {
	var parts []string
	depth, inStr, inRe := 0, rune(0), false
	cur := &strings.Builder{}
	opLen := len(op)
	runes := []rune(expr)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if inStr != 0 {
			cur.WriteRune(c)
			if c == '\\' && i+1 < len(runes) {
				i++
				cur.WriteRune(runes[i])
			} else if c == inStr {
				inStr = 0
			}
			continue
		}
		if inRe {
			cur.WriteRune(c)
			if c == '\\' && i+1 < len(runes) {
				i++
				cur.WriteRune(runes[i])
			} else if c == '/' {
				inRe = false
			}
			continue
		}
		switch c {
		case '"', '\'':
			inStr = c
			cur.WriteRune(c)
		case '/':
			inRe = true
			cur.WriteRune(c)
		case '(':
			depth++
			cur.WriteRune(c)
		case ')':
			depth--
			cur.WriteRune(c)
		default:
			if depth == 0 && i+opLen <= len(runes) && string(runes[i:i+opLen]) == op {
				parts = append(parts, cur.String())
				cur.Reset()
				i += opLen - 1
				continue
			}
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	if len(parts) > 1 {
		return parts
	}
	return []string{expr}
}

func parenMatches(expr string) bool {
	if len(expr) < 2 || expr[0] != '(' || expr[len(expr)-1] != ')' {
		return false
	}
	depth := 0
	for i, c := range expr {
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
		}
		if depth == 0 && i < len(expr)-1 {
			return false
		}
	}
	return depth == 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// Pretty printer
// ═══════════════════════════════════════════════════════════════════════════════

// Print writes a human-readable, colour-coded report to stdout.
func (r *Report) Print() {
	if len(r.Issues) == 0 {
		fmt.Printf("  \033[92m✓\033[0m  %s\n", r.Path)
		return
	}

	fmt.Printf("\n  \033[1m── %s ──\033[0m\n", r.Path)
	for _, iss := range r.Issues {
		var cpfx string
		switch iss.Severity {
		case SevError:
			cpfx = "\033[91m[ERROR]\033[0m"
		case SevWarning:
			cpfx = "\033[93m[WARN] \033[0m"
		case SevInfo:
			cpfx = "\033[96m[INFO] \033[0m"
		}
		loc := "      "
		if iss.Line > 0 {
			loc = fmt.Sprintf("L%-4d ", iss.Line)
		}
		fmt.Printf("  %s  \033[2m%s %-28s\033[0m %s\n",
			cpfx, loc, iss.Field, iss.Message)
	}
}