// Package matcher evaluates boolean matcher expressions.
//
// Supported syntax:
//
//	status_code == 200
//	status_code >= 200 && status_code < 300
//	body contains "text"             (case-insensitive)
//	body not_contains "error"
//	body matches /regex/
//	body starts_with "{"
//	body ends_with "}"
//	url contains "/admin"
//	header["Content-Type"] contains "json"
//	header["X-Powered-By"] == "PHP"
//	oob_received == true
//
// Logical operators:
//
//	expr1 && expr2        AND (higher precedence)
//	expr1 || expr2        OR  (lower precedence)
//	(expr1 || expr2) && expr3
//	not expr / !expr
package matcher

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ResponseCtx is a snapshot of an HTTP response used during evaluation.
type ResponseCtx struct {
	StatusCode  int
	Headers     map[string]string // already lowercase keys
	Body        string
	URL         string
	OOBReceived bool
}

// NewResponseCtx creates a ResponseCtx, normalising header keys to lowercase.
func NewResponseCtx(status int, headers map[string]string, body, url string, oob bool) *ResponseCtx {
	lower := make(map[string]string, len(headers))
	for k, v := range headers {
		lower[strings.ToLower(k)] = v
	}
	return &ResponseCtx{
		StatusCode:  status,
		Headers:     lower,
		Body:        body,
		URL:         url,
		OOBReceived: oob,
	}
}

// EvaluateAll evaluates a list of matcher expressions combined with condition ("and"|"or").
func EvaluateAll(matchers []string, condition string, ctx *ResponseCtx) (bool, error) {
	if len(matchers) == 0 {
		return true, nil
	}
	for _, m := range matchers {
		result, err := Evaluate(m, ctx)
		if err != nil {
			return false, fmt.Errorf("matcher %q: %w", m, err)
		}
		if strings.ToLower(condition) == "or" && result {
			return true, nil
		}
		if strings.ToLower(condition) != "or" && !result {
			return false, nil
		}
	}
	return strings.ToLower(condition) != "or", nil
}

// Evaluate evaluates a single (possibly compound) expression.
func Evaluate(expr string, ctx *ResponseCtx) (bool, error) {
	expr = strings.TrimSpace(expr)

	// OR (lowest precedence) — split first
	orParts, err := logicalSplit(expr, "||")
	if err != nil {
		return false, err
	}
	if len(orParts) > 1 {
		for _, p := range orParts {
			v, err := Evaluate(strings.TrimSpace(p), ctx)
			if err != nil {
				return false, err
			}
			if v {
				return true, nil
			}
		}
		return false, nil
	}

	// AND
	andParts, err := logicalSplit(expr, "&&")
	if err != nil {
		return false, err
	}
	if len(andParts) > 1 {
		for _, p := range andParts {
			v, err := Evaluate(strings.TrimSpace(p), ctx)
			if err != nil {
				return false, err
			}
			if !v {
				return false, nil
			}
		}
		return true, nil
	}

	return evalSingle(expr, ctx)
}

// logicalSplit splits expr by op (|| or &&) respecting parens, quotes, and regex.
func logicalSplit(expr, op string) ([]string, error) {
	var parts []string
	depth := 0
	inStr := rune(0)
	inRe := false
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
			// Check if we have our operator here (at depth == 0)
			if depth == 0 && i+opLen <= len(runes) {
				chunk := string(runes[i : i+opLen])
				if chunk == op {
					parts = append(parts, cur.String())
					cur.Reset()
					i += opLen - 1
					continue
				}
			}
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	if len(parts) > 1 {
		return parts, nil
	}
	return []string{expr}, nil
}

// ordered from longest/most-specific to shortest to avoid prefix collisions
var operators = []string{
	"not_contains", "starts_with", "ends_with",
	"contains", "matches",
	"==", "!=", "<=", ">=", "<", ">",
}

func evalSingle(expr string, ctx *ResponseCtx) (bool, error) {
	expr = strings.TrimSpace(expr)

	// Strip outer parens
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") && matchingParen(expr) {
		return Evaluate(expr[1:len(expr)-1], ctx)
	}

	// NOT prefix
	lower := strings.ToLower(expr)
	if strings.HasPrefix(lower, "not ") {
		v, err := Evaluate(expr[4:], ctx)
		return !v, err
	}
	if strings.HasPrefix(expr, "!") && !strings.HasPrefix(expr, "!=") {
		v, err := Evaluate(expr[1:], ctx)
		return !v, err
	}

	lhsStr, op, rhsStr, err := splitCondition(expr)
	if err != nil {
		return false, err
	}

	lhsVal := getLHS(lhsStr, ctx)
	return applyOp(lhsVal, op, rhsStr)
}

func matchingParen(expr string) bool {
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

func splitCondition(expr string) (lhs, op, rhs string, err error) {
	for _, o := range operators {
		var pat string
		if o[0] >= 'a' && o[0] <= 'z' {
			// word operator — must be surrounded by whitespace
			pat = `(?i)\s+` + regexp.QuoteMeta(o) + `\s+`
		} else {
			pat = `\s*` + regexp.QuoteMeta(o) + `\s*`
		}
		re, reErr := regexp.Compile(pat)
		if reErr != nil {
			continue
		}
		loc := re.FindStringIndex(expr)
		if loc == nil {
			continue
		}
		return strings.TrimSpace(expr[:loc[0]]),
			o,
			strings.TrimSpace(expr[loc[1]:]),
			nil
	}
	return "", "", "", fmt.Errorf("unrecognised matcher: %q", expr)
}

// getLHS resolves the left-hand side identifier to its value.
func getLHS(lhs string, ctx *ResponseCtx) interface{} {
	key := strings.ToLower(strings.TrimSpace(lhs))

	switch key {
	case "status_code", "status":
		return ctx.StatusCode
	case "body":
		return ctx.Body
	case "url":
		return ctx.URL
	case "oob_received":
		return ctx.OOBReceived
	}

	// header["Name"] or header['Name']
	re := regexp.MustCompile(`^headers?\[[\'\"](.+?)[\'\"]\]$`)
	if m := re.FindStringSubmatch(key); m != nil {
		return ctx.Headers[strings.ToLower(m[1])]
	}

	// headers.name
	if strings.HasPrefix(key, "header") {
		parts := strings.SplitN(key, ".", 2)
		if len(parts) == 2 {
			return ctx.Headers[strings.ToLower(parts[1])]
		}
	}

	return ""
}

// applyOp applies the operator to the already-resolved LHS and raw RHS string.
func applyOp(lhs interface{}, op, rhsRaw string) (bool, error) {
	rhsRaw = strings.TrimSpace(rhsRaw)

	// Boolean RHS
	if strings.EqualFold(rhsRaw, "true") {
		rhs := true
		if op == "==" {
			if b, ok := lhs.(bool); ok {
				return b == rhs, nil
			}
		}
		if op == "!=" {
			if b, ok := lhs.(bool); ok {
				return b != rhs, nil
			}
		}
	}
	if strings.EqualFold(rhsRaw, "false") {
		rhs := false
		if op == "==" {
			if b, ok := lhs.(bool); ok {
				return b == rhs, nil
			}
		}
	}

	// Regex RHS for "matches"
	if op == "matches" {
		pattern := rhsRaw
		if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
			pattern = pattern[1 : len(pattern)-1]
		}
		re, err := regexp.Compile("(?is)" + pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex %q: %w", pattern, err)
		}
		return re.MatchString(fmt.Sprintf("%v", lhs)), nil
	}

	// Numeric comparison
	lhsInt, lhsIsInt := lhs.(int)
	rhsInt, rhsConvErr := strconv.Atoi(rhsRaw)

	if lhsIsInt && rhsConvErr == nil {
		switch op {
		case "==":
			return lhsInt == rhsInt, nil
		case "!=":
			return lhsInt != rhsInt, nil
		case "<":
			return lhsInt < rhsInt, nil
		case ">":
			return lhsInt > rhsInt, nil
		case "<=":
			return lhsInt <= rhsInt, nil
		case ">=":
			return lhsInt >= rhsInt, nil
		}
	}

	// String operations
	lhsStr := fmt.Sprintf("%v", lhs)

	// Strip surrounding quotes from RHS
	rhsStr := rhsRaw
	if len(rhsStr) >= 2 && ((rhsStr[0] == '"' && rhsStr[len(rhsStr)-1] == '"') ||
		(rhsStr[0] == '\'' && rhsStr[len(rhsStr)-1] == '\'')) {
		rhsStr = rhsStr[1 : len(rhsStr)-1]
		// Unescape sequences
		rhsStr = strings.ReplaceAll(rhsStr, `\\`, "\x00BACKSLASH\x00") // protect literal backslash first
		rhsStr = strings.ReplaceAll(rhsStr, `\"`, `"`)
		rhsStr = strings.ReplaceAll(rhsStr, `\'`, `'`)
		rhsStr = strings.ReplaceAll(rhsStr, `\n`, "\n")
		rhsStr = strings.ReplaceAll(rhsStr, `\t`, "\t")
		rhsStr = strings.ReplaceAll(rhsStr, `\r`, "\r")
		rhsStr = strings.ReplaceAll(rhsStr, "\x00BACKSLASH\x00", `\`) // restore literal backslash
	}

	switch op {
	case "==":
		return lhsStr == rhsStr, nil
	case "!=":
		return lhsStr != rhsStr, nil
	case "contains":
		return strings.Contains(strings.ToLower(lhsStr), strings.ToLower(rhsStr)), nil
	case "not_contains":
		return !strings.Contains(strings.ToLower(lhsStr), strings.ToLower(rhsStr)), nil
	case "starts_with":
		return strings.HasPrefix(lhsStr, rhsStr), nil
	case "ends_with":
		return strings.HasSuffix(lhsStr, rhsStr), nil
	}

	return false, fmt.Errorf("unknown operator %q", op)
}