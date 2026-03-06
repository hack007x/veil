// Package resolver handles {{variable}} and {{function(args)}} substitution.
//
// Built-in variables (auto-populated from the target URL):
//
//	{{Hostname}}     host only          (e.g. example.com)
//	{{Host}}         host:port          (e.g. example.com:8080)
//	{{BaseURL}}      scheme://host:port
//	{{RootURL}}      alias for BaseURL
//	{{Scheme}}       http | https
//	{{Port}}         port as string
//	{{Path}}         URL path
//	{{random_ua}}    random browser User-Agent
//	{{timestamp}}    current Unix timestamp
//	{{oob_domain}}   OOB callback domain
//	{{oob_url}}      http://{{oob_domain}}
//
// Built-in functions:
//
//	{{base64(x)}}           base64-encode
//	{{base64_decode(x)}}    base64-decode
//	{{url_encode(x)}}       percent-encode
//	{{url_decode(x)}}       percent-decode
//	{{md5(x)}}              MD5 hex
//	{{sha1(x)}}             SHA-1 hex
//	{{sha256(x)}}           SHA-256 hex
//	{{hex_encode(x)}}       hex-encode bytes
//	{{hex_decode(x)}}       decode hex → UTF-8
//	{{to_lower(x)}}         lowercase
//	{{to_upper(x)}}         uppercase
//	{{trim(x)}}             strip whitespace
//	{{len(x)}}              string length
//	{{reverse(x)}}          reverse string
//	{{replace(x,old,new)}}  string replace
//	{{concat(a,b,...)}}     concatenate
//	{{random_str(n)}}       random lowercase string
//	{{random_int(min,max)}} random integer
package resolver

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
}

// Resolver resolves {{...}} placeholders in strings.
type Resolver struct {
	vars map[string]string
}

// New creates a Resolver pre-populated with variables derived from targetURL,
// global template variables, and optional OOB domain.
func New(targetURL string, globalVars map[string]string, oobDomain string) *Resolver {
	r := &Resolver{vars: make(map[string]string)}

	// Parse target URL
	parsed, err := url.Parse(targetURL)
	if err == nil {
		host := parsed.Hostname()
		port := parsed.Port()
		if port == "" {
			if parsed.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		netloc := host + ":" + port
		r.vars["Hostname"] = host
		r.vars["Host"] = netloc
		r.vars["BaseURL"] = parsed.Scheme + "://" + netloc
		r.vars["RootURL"] = parsed.Scheme + "://" + netloc
		r.vars["Scheme"] = parsed.Scheme
		r.vars["Port"] = port
		if parsed.Path != "" {
			r.vars["Path"] = parsed.Path
		} else {
			r.vars["Path"] = "/"
		}
	}

	// OOB
	if oobDomain != "" {
		r.vars["oob_domain"] = oobDomain
		r.vars["oob_host"] = oobDomain
		r.vars["oob_url"] = "http://" + oobDomain
	}

	// Template globals (lower priority than extracted vars, added last)
	for k, v := range globalVars {
		r.vars[k] = v
	}

	return r
}

// AddVars merges additional variables (e.g. extracted from a previous response).
func (r *Resolver) AddVars(extra map[string]string) {
	for k, v := range extra {
		r.vars[k] = v
	}
}

// Resolve replaces all {{...}} in text.
func (r *Resolver) Resolve(text string) string {
	if !strings.Contains(text, "{{") {
		return text
	}
	// Iterative resolution handles nested: {{base64({{payload}})}}
	for i := 0; i < 8; i++ {
		prev := text
		text = varPattern.ReplaceAllStringFunc(text, func(match string) string {
			inner := match[2 : len(match)-2]
			return r.eval(strings.TrimSpace(inner))
		})
		if text == prev {
			break
		}
	}
	return text
}

// ResolveMap resolves both keys and values of a string map.
func (r *Resolver) ResolveMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[r.Resolve(k)] = r.Resolve(v)
	}
	return out
}

// varPattern matches {{...}} but not nested braces (resolved iteratively).
var varPattern = regexp.MustCompile(`\{\{[^{}]+\}\}`)

// eval resolves a single expression (no surrounding braces).
func (r *Resolver) eval(expr string) string {
	// Function call: name(args)
	if idx := strings.Index(expr, "("); idx > 0 && strings.HasSuffix(expr, ")") {
		name := expr[:idx]
		argsRaw := expr[idx+1 : len(expr)-1]
		return r.callFn(name, argsRaw)
	}

	// Dynamic built-ins
	switch strings.ToLower(expr) {
	case "random_ua":
		return userAgents[rand.Intn(len(userAgents))]
	case "timestamp":
		return strconv.FormatInt(time.Now().Unix(), 10)
	}

	// Stored variable (case-sensitive first)
	if v, ok := r.vars[expr]; ok {
		return v
	}
	// Case-insensitive fallback
	lower := strings.ToLower(expr)
	for k, v := range r.vars {
		if strings.ToLower(k) == lower {
			return v
		}
	}

	// Unknown — return as-is
	return "{{" + expr + "}}"
}

// callFn dispatches a built-in function.
func (r *Resolver) callFn(name, argsRaw string) string {
	rawArgs := splitArgs(argsRaw)
	args := make([]string, len(rawArgs))
	for i, a := range rawArgs {
		a = strings.TrimSpace(a)
		if len(a) >= 2 && (a[0] == '"' || a[0] == '\'') {
			a = a[1 : len(a)-1]
		} else if strings.Contains(a, "{{") {
			a = r.Resolve(a)
		} else {
			// Plain word — could be a variable name
			if v, ok := r.vars[a]; ok {
				a = v
			}
		}
		args[i] = a
	}

	switch name {
	case "base64":
		if len(args) < 1 {
			return ""
		}
		return base64.StdEncoding.EncodeToString([]byte(args[0]))
	case "base64_decode":
		if len(args) < 1 {
			return ""
		}
		b, err := base64.StdEncoding.DecodeString(args[0] + "==")
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(args[0])
			if err != nil {
				return ""
			}
		}
		return string(b)
	case "url_encode":
		if len(args) < 1 {
			return ""
		}
		return url.QueryEscape(args[0])
	case "url_decode":
		if len(args) < 1 {
			return ""
		}
		v, _ := url.QueryUnescape(args[0])
		return v
	case "md5":
		if len(args) < 1 {
			return ""
		}
		h := md5.Sum([]byte(args[0]))
		return hex.EncodeToString(h[:])
	case "sha1":
		if len(args) < 1 {
			return ""
		}
		h := sha1.Sum([]byte(args[0]))
		return hex.EncodeToString(h[:])
	case "sha256":
		if len(args) < 1 {
			return ""
		}
		h := sha256.Sum256([]byte(args[0]))
		return hex.EncodeToString(h[:])
	case "hex_encode":
		if len(args) < 1 {
			return ""
		}
		return hex.EncodeToString([]byte(args[0]))
	case "hex_decode":
		if len(args) < 1 {
			return ""
		}
		b, err := hex.DecodeString(args[0])
		if err != nil {
			return ""
		}
		return string(b)
	case "to_lower":
		if len(args) < 1 {
			return ""
		}
		return strings.ToLower(args[0])
	case "to_upper":
		if len(args) < 1 {
			return ""
		}
		return strings.ToUpper(args[0])
	case "trim":
		if len(args) < 1 {
			return ""
		}
		return strings.TrimSpace(args[0])
	case "len":
		if len(args) < 1 {
			return "0"
		}
		return strconv.Itoa(len(args[0]))
	case "reverse":
		if len(args) < 1 {
			return ""
		}
		runes := []rune(args[0])
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		return string(runes)
	case "replace":
		if len(args) < 3 {
			return ""
		}
		return strings.ReplaceAll(args[0], args[1], args[2])
	case "concat":
		return strings.Join(args, "")
	case "random_str":
		n := 8
		if len(args) >= 1 {
			if v, err := strconv.Atoi(args[0]); err == nil {
				n = v
			}
		}
		const letters = "abcdefghijklmnopqrstuvwxyz"
		b := make([]byte, n)
		for i := range b {
			b[i] = letters[rand.Intn(len(letters))]
		}
		return string(b)
	case "random_int":
		mn, mx := 0, 65535
		if len(args) >= 2 {
			if v, err := strconv.Atoi(args[0]); err == nil {
				mn = v
			}
			if v, err := strconv.Atoi(args[1]); err == nil {
				mx = v
			}
		}
		if mx <= mn {
			return strconv.Itoa(mn)
		}
		return strconv.Itoa(mn + rand.Intn(mx-mn))
	}

	// Unknown function — return raw
	return fmt.Sprintf("{{%s(%s)}}", name, argsRaw)
}

// splitArgs splits function arguments while respecting quotes.
func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote := rune(0)

	for _, c := range s {
		switch {
		case inQuote != 0:
			cur.WriteRune(c)
			if c == inQuote {
				inQuote = 0
			}
		case c == '"' || c == '\'':
			inQuote = c
			cur.WriteRune(c)
		case c == ',':
			args = append(args, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}
