// Package parser implements the .poc template file parser.
//
// Syntax overview:
//
//	## key: value        → metadata
//	#$ name = "value"   → variable definition
//	#$ name = val1 | val2 | val3   → multi-value variable (pipe-separated)
//	#$ name = @file(path.txt)      → load values from file (one per line)
//	METHOD /path HTTP/x → HTTP request line
//	Header: Value       → request header
//	                    → blank line separates headers from body
//	body text...
//	#@ matcher: EXPR    → matcher / directive
//	#@ attack: MODE     → attack mode (sniper/pitchfork/clusterbomb)
//	#> extract: ...     → extractor
//	---                 → separator between multiple requests
package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tpl "github.com/hack007x/veil/template"
)

// ParseError is returned when a .poc file cannot be parsed.
type ParseError struct {
	File string
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	if e.File != "" {
		return fmt.Sprintf("parse error in %s (line %d): %s", e.File, e.Line, e.Msg)
	}
	return fmt.Sprintf("parse error (line %d): %s", e.Line, e.Msg)
}

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
	"CONNECT": true,
}

// Parse parses the content of a .poc file and returns a PocTemplate.
func Parse(content, filePath string) (*tpl.PocTemplate, error) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	t := &tpl.PocTemplate{
		Path:       filePath,
		Variables:  make(map[string]string),
		ListVars:   make(map[string][]string),
		AttackMode: tpl.AttackSniper,
		Metadata:   tpl.Metadata{Severity: "info"},
	}

	// Split content into blocks separated by "---"
	blocks := splitBlocks(content)

	reqIdx := 0
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		hadReq, err := parseBlock(block, t, reqIdx)
		if err != nil {
			return nil, &ParseError{File: filePath, Msg: err.Error()}
		}
		if hadReq {
			reqIdx++
		}
	}

	return t, nil
}

// splitBlocks splits the content on lines that are only "---" (with optional whitespace).
func splitBlocks(content string) []string {
	lines := strings.Split(content, "\n")
	var blocks []string
	var cur []string

	for _, line := range lines {
		if strings.TrimSpace(line) == "---" {
			blocks = append(blocks, strings.Join(cur, "\n"))
			cur = nil
		} else {
			cur = append(cur, line)
		}
	}
	if len(cur) > 0 {
		blocks = append(blocks, strings.Join(cur, "\n"))
	}
	return blocks
}

type parseState int

const (
	statePre        parseState = iota
	stateHeaders    parseState = iota
	stateBody       parseState = iota
	stateDirectives parseState = iota
)

func parseBlock(block string, t *tpl.PocTemplate, reqIdx int) (bool, error) {
	lines := strings.Split(block, "\n")
	state := statePre

	var req *tpl.HttpRequest
	var bodyLines []string

	for _, rawLine := range lines {
		stripped := strings.TrimSpace(rawLine)

		isMeta      := strings.HasPrefix(stripped, "## ")
		isVar       := strings.HasPrefix(stripped, "#$ ")
		isMatcher   := strings.HasPrefix(stripped, "#@ ")
		isExtractor := strings.HasPrefix(stripped, "#> ")
		// Pure comment: starts with # but not ##, #@, #$, #>
		isComment   := len(stripped) > 1 && stripped[0] == '#' &&
			stripped[1] != '#' && stripped[1] != '@' &&
			stripped[1] != '$' && stripped[1] != '>'

		if isComment || stripped == "#" {
			continue
		}

		switch state {
		case statePre:
			switch {
			case isMeta:
				parseMeta(stripped[3:], &t.Metadata)
			case isVar:
				parseVar(stripped[3:], t)
			case isMatcher, isExtractor:
				// directives before any request — ignore
			default:
				// Try to parse as HTTP request line
				parts := strings.Fields(stripped)
				if len(parts) >= 2 && httpMethods[parts[0]] {
					req = &tpl.HttpRequest{
						Index:           reqIdx,
						Method:          parts[0],
						Path:            parts[1],
						Headers:         make(map[string]string),
						Condition:       "and",
						FollowRedirects: true,
						Timeout:         10,
					}
					t.Requests = append(t.Requests, *req)
					req = &t.Requests[len(t.Requests)-1]
					state = stateHeaders
				}
			}

		case stateHeaders:
			switch {
			case stripped == "":
				state = stateBody
			case isMatcher:
				state = stateDirectives
				parseDirective(stripped[3:], req, t)
			case isExtractor:
				state = stateDirectives
				parseExtractor(stripped[3:], req)
			case isVar:
				parseVar(stripped[3:], t)
			case isMeta:
				parseMeta(stripped[3:], &t.Metadata)
			default:
				if idx := strings.Index(stripped, ":"); idx > 0 {
					key := strings.TrimSpace(stripped[:idx])
					val := strings.TrimSpace(stripped[idx+1:])
					req.Headers[key] = val
				}
			}

		case stateBody:
			switch {
			case isMatcher:
				if len(bodyLines) > 0 {
					req.Body = strings.TrimSpace(strings.Join(bodyLines, "\n"))
					bodyLines = nil
				}
				state = stateDirectives
				parseDirective(stripped[3:], req, t)
			case isExtractor:
				if len(bodyLines) > 0 {
					req.Body = strings.TrimSpace(strings.Join(bodyLines, "\n"))
					bodyLines = nil
				}
				state = stateDirectives
				parseExtractor(stripped[3:], req)
			default:
				bodyLines = append(bodyLines, rawLine)
			}

		case stateDirectives:
			switch {
			case isMatcher:
				parseDirective(stripped[3:], req, t)
			case isExtractor:
				parseExtractor(stripped[3:], req)
			case isVar:
				parseVar(stripped[3:], t)
			case isMeta:
				parseMeta(stripped[3:], &t.Metadata)
			}
		}
	}

	// Flush remaining body
	if state == stateBody && req != nil && len(bodyLines) > 0 {
		req.Body = strings.TrimSpace(strings.Join(bodyLines, "\n"))
	}

	return req != nil, nil
}

// parseMeta parses "key: value" after stripping "## ".
func parseMeta(line string, m *tpl.Metadata) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return
	}
	key := strings.TrimSpace(strings.ToLower(line[:idx]))
	val := strings.TrimSpace(line[idx+1:])

	switch key {
	case "id":
		m.ID = val
	case "name":
		m.Name = val
	case "author":
		m.Author = val
	case "severity":
		m.Severity = strings.ToLower(val)
	case "cve":
		m.CVE = val
	case "tags":
		for _, t := range strings.Split(val, ",") {
			if t = strings.TrimSpace(t); t != "" {
				m.Tags = append(m.Tags, t)
			}
		}
	case "description":
		m.Description = val
	case "affects":
		m.Affects = val
	case "reference", "references":
		m.References = append(m.References, val)
	case "cvss-score":
		m.CVSSScore = val
	case "shodan-query":
		m.ShodanQuery = val
	case "fofa-query":
		m.FofaQuery = val
	case "verification":
		m.Verification = strings.ToLower(val)
	}
}

// parseVar parses variable definitions after stripping "#$ ".
// Supports:
//   - Single value:    name = "value" or name = value
//   - Multi-value:     name = val1 | val2 | val3
//   - File loading:    name = @file(path.txt)
func parseVar(line string, t *tpl.PocTemplate) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return
	}
	name := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+1:])

	// Strip surrounding quotes (only for the entire value, not for pipe-separated)
	if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') ||
		(val[0] == '\'' && val[len(val)-1] == '\'')) {
		// Check if this is a simple quoted string (no pipes inside)
		inner := val[1 : len(val)-1]
		if !strings.Contains(inner, "|") {
			val = inner
		}
	}

	// Check for @file(path) syntax
	if strings.HasPrefix(val, "@file(") && strings.HasSuffix(val, ")") {
		filePath := val[6 : len(val)-1]
		filePath = strings.TrimSpace(filePath)
		// Strip quotes from file path
		if len(filePath) >= 2 && ((filePath[0] == '"' && filePath[len(filePath)-1] == '"') ||
			(filePath[0] == '\'' && filePath[len(filePath)-1] == '\'')) {
			filePath = filePath[1 : len(filePath)-1]
		}
		// Resolve relative paths based on the template file's directory
		if !filepath.IsAbs(filePath) && t.Path != "" {
			dir := filepath.Dir(t.Path)
			filePath = filepath.Join(dir, filePath)
		}
		values := loadFileValues(filePath)
		if len(values) > 0 {
			t.ListVars[name] = values
			t.Variables[name] = values[0] // first value as default for single-value compat
		}
		return
	}

	// Check for pipe-separated multi-value: val1 | val2 | val3
	if strings.Contains(val, "|") {
		parts := strings.Split(val, "|")
		var values []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			// Strip quotes from individual values
			if len(p) >= 2 && ((p[0] == '"' && p[len(p)-1] == '"') ||
				(p[0] == '\'' && p[len(p)-1] == '\'')) {
				p = p[1 : len(p)-1]
			}
			if p != "" {
				values = append(values, p)
			}
		}
		if len(values) > 1 {
			t.ListVars[name] = values
			t.Variables[name] = values[0] // first value as default
			return
		}
		// Only one value after splitting — treat as single
		if len(values) == 1 {
			val = values[0]
		}
	}

	t.Variables[name] = val
}

// loadFileValues reads lines from a file, returning non-empty, non-comment lines.
func loadFileValues(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var values []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		values = append(values, line)
	}
	return values
}

// parseDirective parses "#@ key: value" after stripping "#@ ".
func parseDirective(line string, req *tpl.HttpRequest, t *tpl.PocTemplate) {
	if req == nil {
		return
	}
	idx := strings.Index(line, ":")
	if idx < 0 {
		return
	}
	key := strings.TrimSpace(strings.ToLower(line[:idx]))
	val := strings.TrimSpace(line[idx+1:])

	switch key {
	case "matcher":
		req.Matchers = append(req.Matchers, val)
	case "condition":
		req.Condition = strings.ToLower(val)
	case "follow_redirects":
		req.FollowRedirects = val == "true" || val == "1" || val == "yes"
	case "timeout":
		if n, err := strconv.Atoi(val); err == nil {
			req.Timeout = n
		}
	case "oob":
		req.OOB = tpl.OOBType(strings.ToLower(val))
	case "attack":
		mode := strings.ToLower(val)
		switch mode {
		case "sniper":
			t.AttackMode = tpl.AttackSniper
		case "pitchfork":
			t.AttackMode = tpl.AttackPitchfork
		case "clusterbomb":
			t.AttackMode = tpl.AttackClusterbomb
		}
	}
}

// parseExtractor parses "#> extract: name=X, from=Y, method=Z" after stripping "#> ".
func parseExtractor(line string, req *tpl.HttpRequest) {
	if req == nil {
		return
	}
	idx := strings.Index(line, ":")
	if idx < 0 {
		return
	}
	key := strings.TrimSpace(strings.ToLower(line[:idx]))
	if key != "extract" {
		return
	}

	kv := parseKV(line[idx+1:])

	ext := tpl.Extractor{
		Source: "body",
		Group:  1,
	}
	ext.Name = kv["name"]
	if v, ok := kv["from"]; ok {
		ext.Source = v
	}
	if v, ok := kv["internal"]; ok {
		ext.Internal = v == "true" || v == "1"
	}
	if v, ok := kv["group"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			ext.Group = n
		}
	}

	switch {
	case kv["regex"] != "":
		ext.Method = tpl.ExtractRegex
		ext.Pattern = kv["regex"]
	case kv["json"] != "":
		ext.Method = tpl.ExtractJSON
		ext.Pattern = kv["json"]
	case kv["xpath"] != "":
		ext.Method = tpl.ExtractXPath
		ext.Pattern = kv["xpath"]
	case kv["kval"] != "":
		ext.Method = tpl.ExtractKVal
		ext.Pattern = kv["kval"]
	}

	if ext.Name != "" {
		req.Extractors = append(req.Extractors, ext)
	}
}

// parseKV parses comma-separated key=value pairs.
// Supports: key="quoted", key=/regex/, key=plain
func parseKV(s string) map[string]string {
	result := make(map[string]string)
	s = strings.TrimSpace(s)
	i := 0

	for i < len(s) {
		// Skip whitespace / commas
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			break
		}

		// Read key
		keyStart := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' && s[i] != '\t' && s[i] != ',' {
			i++
		}
		key := strings.ToLower(strings.TrimSpace(s[keyStart:i]))
		if key == "" {
			i++
			continue
		}

		// Skip whitespace
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			result[key] = ""
			continue
		}
		i++ // skip '='

		// Skip whitespace after '='
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
			// Regex: /pattern/
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
				i++ // skip closing /
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
				i++ // skip closing quote
			}
		default:
			// Unquoted — read until comma
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
