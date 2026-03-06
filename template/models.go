package template

// Metadata holds the ## header fields of a .poc template.
type Metadata struct {
	ID           string   // unique template identifier (required)
	Name         string   // human-readable name (required)
	Author       string   // template author (required)
	Severity     string   // critical | high | medium | low | info (required)
	CVE          string
	Tags         []string
	Description  string
	Affects      string   // affected software / versions
	References   []string
	CVSSScore    string   // CVSS score (e.g. "6.4")
	ShodanQuery  string   // Shodan search dork
	FofaQuery    string   // FOFA search dork
	Verification string   // "true" | "false" — whether verified
}

// ExtractMethod is the strategy used to pull a value from a response.
type ExtractMethod string

const (
	ExtractRegex ExtractMethod = "regex"
	ExtractJSON  ExtractMethod = "json"
	ExtractXPath ExtractMethod = "xpath"
	ExtractKVal  ExtractMethod = "kval"
)

// Extractor defines a single value-extraction rule.
type Extractor struct {
	Name     string        // variable name to store the result
	Source   string        // body | header["X"] | url | status_code | headers
	Method   ExtractMethod // regex | json | xpath | kval
	Pattern  string        // regex pattern, JSON path, XPath, or key name
	Group    int           // regex capture group (1-indexed; 0 = whole match)
	Internal bool          // if true, suppress from printed output
}

// OOBType is the kind of out-of-band callback expected.
type OOBType string

const (
	OOBNone OOBType = ""
	OOBDNS  OOBType = "dns"
	OOBHTTP OOBType = "http"
)

// AttackMode controls how multi-value variables are combined.
type AttackMode string

const (
	AttackSniper      AttackMode = "sniper"      // one variable at a time, others use first value
	AttackPitchfork   AttackMode = "pitchfork"   // zip: all variables advance in lock-step
	AttackClusterbomb AttackMode = "clusterbomb"  // cartesian product of all variable values
)

// HttpRequest is one request block inside a .poc file.
type HttpRequest struct {
	Index           int
	Method          string
	Path            string
	Headers         map[string]string
	Body            string
	Matchers        []string  // raw matcher expression strings
	Condition       string    // "and" | "or"
	Extractors      []Extractor
	FollowRedirects bool
	Timeout         int // seconds
	OOB             OOBType
}

// PocTemplate is the parsed representation of a .poc file.
type PocTemplate struct {
	Path       string
	Metadata   Metadata
	Variables  map[string]string   // single-value variables (backward compatible)
	ListVars   map[string][]string // multi-value variables (pipe-separated or @file)
	AttackMode AttackMode          // sniper | pitchfork | clusterbomb (default: sniper)
	Requests   []HttpRequest
}

// RequestResponse stores one raw HTTP request/response pair.
type RequestResponse struct {
	Request     string // raw HTTP request
	Response    string // raw HTTP response
	CURLCommand string // curl command to reproduce the request
}

// ScanResult is the outcome of running one template against one target.
type ScanResult struct {
	Target       string
	TemplateID   string
	TemplateName string
	TemplatePath string
	Vulnerable   bool
	Severity     string
	CVE          string
	Tags         []string
	MatchedAt    string
	Extracted    map[string]string
	MatchedVars  map[string]string // variable values that triggered the match
	Error        string

	// Enriched metadata from template
	Author      string
	Description string
	Affects     string
	References  []string
	CVSSScore   string
	ShodanQuery string
	FofaQuery   string

	// Raw request/response pairs (one per request in the template)
	Interactions []RequestResponse
}