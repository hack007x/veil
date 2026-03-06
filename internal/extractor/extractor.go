// Package extractor pulls values from HTTP responses using various methods.
package extractor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	tpl "github.com/hack007x/veil/template"
)

// Engine runs extractors against response data.
type Engine struct{}

// New returns a new Engine.
func New() *Engine { return &Engine{} }

// Extract runs a single extractor and returns the extracted string, or "" if not found.
func (e *Engine) Extract(ext tpl.Extractor, statusCode int, headers map[string]string, body, finalURL string) string {
	source := e.getSource(ext.Source, statusCode, headers, body, finalURL)

	switch ext.Method {
	case tpl.ExtractRegex:
		return e.extractRegex(source, ext.Pattern, ext.Group)
	case tpl.ExtractJSON:
		return e.extractJSON(source, ext.Pattern)
	case tpl.ExtractXPath:
		return e.extractXPath(source, ext.Pattern)
	case tpl.ExtractKVal:
		return e.extractKVal(source, ext.Pattern)
	}
	return ""
}

// ── Source resolution ─────────────────────────────────────────────────────────

func (e *Engine) getSource(source string, statusCode int, headers map[string]string, body, finalURL string) string {
	norm := make(map[string]string, len(headers))
	for k, v := range headers {
		norm[strings.ToLower(k)] = v
	}

	s := strings.TrimSpace(source)
	switch strings.ToLower(s) {
	case "body", "":
		return body
	case "url":
		return finalURL
	case "status_code", "status":
		return strconv.Itoa(statusCode)
	case "header", "headers":
		sb := strings.Builder{}
		for k, v := range norm {
			sb.WriteString(k + ": " + v + "\n")
		}
		return sb.String()
	}

	// header["Name"] or header['Name']
	re := regexp.MustCompile(`(?i)^headers?\[[\'\"](.+?)[\'\"]\]$`)
	if m := re.FindStringSubmatch(s); m != nil {
		return norm[strings.ToLower(m[1])]
	}

	// headers.name
	if re2 := regexp.MustCompile(`(?i)^headers?\.(.+)$`); re2.MatchString(s) {
		parts := strings.SplitN(s, ".", 2)
		if len(parts) == 2 {
			return norm[strings.ToLower(parts[1])]
		}
	}

	return body // default
}

// ── Extraction methods ────────────────────────────────────────────────────────

func (e *Engine) extractRegex(text, pattern string, group int) string {
	re, err := regexp.Compile("(?is)" + pattern)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	if group < len(m) {
		return m[group]
	}
	if len(m) > 0 {
		return m[0]
	}
	return ""
}

func (e *Engine) extractJSON(text, path string) string {
	var data interface{}
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		return ""
	}

	// Strip leading $. or .
	path = strings.TrimPrefix(path, "$")
	path = strings.TrimPrefix(path, ".")

	parts := strings.Split(path, ".")
	current := data
	for _, part := range parts {
		if part == "" {
			continue
		}
		switch v := current.(type) {
		case map[string]interface{}:
			val, ok := v[part]
			if !ok {
				return ""
			}
			current = val
		case []interface{}:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(v) {
				return ""
			}
			current = v[idx]
		default:
			return ""
		}
	}

	if current == nil {
		return ""
	}
	return fmt.Sprintf("%v", current)
}

func (e *Engine) extractXPath(text, _ string) string {
	// XPath requires an external library not in stdlib.
	// Leaving a clear stub; users can integrate golang.org/x/net/html or antchfx/xpath.
	_ = text
	return ""
}

func (e *Engine) extractKVal(text, key string) string {
	pattern := fmt.Sprintf(`(?i)%s\s*[=:]\s*([^\s,;&'"<>]+)`, regexp.QuoteMeta(key))
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(text)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}
