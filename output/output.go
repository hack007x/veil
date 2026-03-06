// Package output handles all terminal display and JSON/HTML reporting.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	tpl "github.com/hack007x/veil/template"
)

// ── ANSI palette ──────────────────────────────────────────────────────────────

const (
	rst  = "\033[0m"
	dim  = "\033[2m"

	fgRed     = "\033[91m"
	fgGreen   = "\033[92m"
	fgYellow  = "\033[93m"
	fgMagenta = "\033[95m"
	fgCyan    = "\033[96m"

	bRed = "\033[1;91m"
	bYel = "\033[1;93m"
	bBlu = "\033[1;94m"
	bCyn = "\033[1;96m"
	bGrn = "\033[1;92m"
	bWht = "\033[1;97m"
	dCyn = "\033[2;96m"
	dGry = "\033[2;37m"
)

func sevColor(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return bRed
	case "high":
		return bYel
	case "medium":
		return bBlu
	case "low":
		return bCyn
	default:
		return bGrn
	}
}

func sevLabel(s string) string {
	lower := strings.ToLower(s)
	label := lower
	if label == "" {
		label = "info"
	}
	switch lower {
	case "critical":
		return bRed + label + rst
	case "high":
		return bYel + label + rst
	case "medium":
		return bBlu + label + rst
	case "low":
		return bCyn + label + rst
	default:
		return bGrn + label + rst
	}
}

// ── Banner ────────────────────────────────────────────────────────────────────

func Banner() {
  fmt.Printf(`
%s                     *     *                                    🌙
          *                 *          *         *           *             
                                                      *             *    
                        *            *         *                   ___   
  *               *                                          |     | |   
        *              _________##                 *        / \    | |   
                      @\\\\\\\\\##    *     |              |--o|===|-|   
  *                  @@@\\\\\\\\##\       \|/|/            |---|   | |   
                    @@ @@\\\\\\\\\\\    \|\\|//|/     *   /  *  \  |V|   
             *     @@@@@@@\\\\\\\\\\\    \|\|/|/         | *     | |E|   
                  @@@@@@@@@----------|    \\|//          |    *  |=|I|   
       __         @@ @@@ @@__________|     \|/           |  v1.0 | |L|   
  ____|_@|_       @@@@@@@@@__________|     \|/           |_______| |_|   
=|__ _____ |=     @@@@ .@@@__________|      |             |@| |@|  | |   
____0_____0__\|/__@@@@__@@@__________|_\|/__|___\|/__\|/___________|_|_  %s

              %s                       [https://github.com/hack007x/veil]%s
                                                                  

`,
    fgCyan, rst,
    bCyn, rst)
}
// ── Scan info table ───────────────────────────────────────────────────────────

// Filters holds optional scan filter values for display in the info table.
type Filters struct {
	IDs        []string
	Severities []string
	Tags       []string
	CVEs       []string
}

// PrintScanInfo prints the pre-scan configuration summary table.
func PrintScanInfo(templates, targets, concurrency, timeout int, proxy string, noSSL, noFollow bool, oobProvider, outputFile string, f Filters) {
	infoRow("Templates",  fmt.Sprintf("%s%d loaded%s", dim, templates, rst))
	if len(f.IDs) > 0 {
		infoRow("ID",       dim+strings.Join(f.IDs, ", ")+rst)
	}
	if len(f.Severities) > 0 {
		infoRow("Severity", dim+strings.Join(f.Severities, ", ")+rst)
	}
	if len(f.Tags) > 0 {
		infoRow("Tags",     dim+strings.Join(f.Tags, ", ")+rst)
	}
	if len(f.CVEs) > 0 {
		infoRow("CVE",      dim+strings.Join(f.CVEs, ", ")+rst)
	}
	infoRow("Targets",    fmt.Sprintf("%s%d%s", dim, targets, rst))
	infoRow("Threads",    fmt.Sprintf("%s%d goroutines%s", dim, concurrency, rst))
	infoRow("Timeout",    fmt.Sprintf("%s%ds%s", dim, timeout, rst))
	infoRow("SSL Verify", onOff(!noSSL))
	infoRow("Redirects",  onOff(!noFollow))
	if oobProvider != "" {
		infoRow("OOB", bGrn+"✓"+rst+"  "+dim+oobProvider+rst)
	} else {
		infoRow("OOB", dim+"✗"+rst)
	}
	if proxy != "" {
		infoRow("Proxy",  dim+proxy+rst)
	}
	if outputFile != "" {
		infoRow("Output", dim+outputFile+rst)
	}
	infoRow("Started", dim+time.Now().Format("2006-01-02 15:04:05")+rst)
	fmt.Println()
}

// PrintInfo prints a single status line in the same style as the scan table.
// Used for pre-scan messages before the table is printed.
func PrintInfo(label, val string) {
	fmt.Printf("  %s[*]  %-12s%s  %s%s%s\n", dCyn, label, rst, dim, val, rst)
}

func infoRow(label, val string) {
	fmt.Printf("  %s[*]  %-12s%s  %s\n", dCyn, label, rst, val)
}

func onOff(b bool) string {
	if b {
		return bGrn + "✓" + rst
	}
	return dim + "✗" + rst
}

// ── Result line (non-verbose mode) ────────────────────────────────────────────

func PrintResult(r *tpl.ScanResult, verbose bool) {
	if !r.Vulnerable {
		return
	}

	ts := dGry + "[" + time.Now().Format("2006-01-02 15:04:05") + "]" + rst

	id := ""
	if r.TemplateID != "" {
		id = " " + dGry + "[" + rst + fgCyan + r.TemplateID + rst + dGry + "]" + rst
	}

	sev := " " + dGry + "[" + rst + sevLabel(r.Severity) + dGry + "]" + rst

	url := " " + sevColor(r.Severity) + r.MatchedAt + rst

	evidence := ""
	if len(r.Extracted) > 0 {
		parts := make([]string, 0, len(r.Extracted))
		for k, v := range r.Extracted {
			snip := v
			if len(snip) > 80 {
				snip = snip[:80] + "…"
			}
			parts = append(parts, dGry+"["+rst+dim+k+rst+dGry+":"+rst+fgYellow+snip+rst+dGry+"]"+rst)
		}
		evidence = " " + strings.Join(parts, " ")
	}

	if !verbose {
		fmt.Printf("\r%s\r", strings.Repeat(" ", 100))
	}
	fmt.Printf("  %s%s%s%s%s\n", ts, id, sev, url, evidence)
}

func PrintResultVerbose(_ *tpl.ScanResult) {}

// ── Progress bar ──────────────────────────────────────────────────────────────

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
var spinIdx int

func PrintProgress(done, total, targets, templates int, elapsed float64) {
	const trackW = 42
	const blockW = 6

	pos := 0
	if total > 0 && done > 0 {
		pos = done * (trackW - blockW) / total
		if pos > trackW-blockW {
			pos = trackW - blockW
		}
	}

	before := strings.Repeat("─", pos)
	block := strings.Repeat("━", blockW)
	after := strings.Repeat("─", trackW-blockW-pos)

	bar := dim + before + rst + fgGreen + block + rst + dim + after + rst

	spin := fgCyan + spinnerFrames[spinIdx%len(spinnerFrames)] + rst
	spinIdx++

	fmt.Printf("\r  %s[%s%s]%s %s  Targets: %s%d%s | PoC: %s%d%s | %s%.1fs%s  ",
		dCyn, bar, dCyn, rst,
		spin,
		bWht, targets, rst,
		bWht, templates, rst,
		dCyn, elapsed, rst,
	)
}

func ClearProgress() {
	fmt.Printf("\r%s\r", strings.Repeat(" ", 90))
}

func PrintSummary(_ []*tpl.ScanResult, _ float64, _ bool) {}

// ── Verbose: request / response display ──────────────────────────────────────

func PrintVerboseRequest(method, rawURL string, headers map[string]string, body string) {
	fmt.Printf("\n  %s┌─ REQ %s %s%s%s\n",
		dCyn, rst, bWht, method, rst)
	fmt.Printf("  %s│%s  %s%s%s\n", dCyn, rst, fgCyan, rawURL, rst)

	for k, v := range headers {
		snip := v
		if len(snip) > 80 {
			snip = snip[:80] + "…"
		}
		fmt.Printf("  %s│%s  %s%s%s: %s\n", dCyn, rst, dim, k, rst, snip)
	}
	if body != "" {
		snip := body
		if len(snip) > 200 {
			snip = snip[:200] + "…"
		}
		fmt.Printf("  %s│%s  %s[body]%s %s\n", dCyn, rst, fgMagenta, rst, snip)
	}
}

func PrintVerboseResponse(status int, finalURL string, bodyLen int, elapsed float64) {
	col := bGrn
	switch {
	case status >= 500:
		col = bRed
	case status >= 400:
		col = bYel
	case status >= 300:
		col = bBlu
	}
	fmt.Printf("  %s└─ RSP%s  %s%d%s  %s%.0fms%s  %s%db%s  %s%s%s\n",
		dCyn, rst,
		col, status, rst,
		dCyn, elapsed*1000, rst,
		dim, bodyLen, rst,
		dim, finalURL, rst)
}

func PrintVerboseSkip(target, reason string) {
	fmt.Printf("  %s[SKIP]%s  %s%s%s  %s%s%s\n",
		fgYellow, rst, dim, target, rst, fgYellow, reason, rst)
}

func PrintVerboseMiss(templateName, target string) {
	fmt.Printf("  %s[MISS]%s  %s%s%s  %s%s%s\n",
		dim, rst, dim, templateName, rst, dim, target, rst)
}

func PrintVerboseError(templateName, target, errMsg string) {
	fmt.Printf("  %s[ERR] %s  %s%s%s  %s→%s  %s%s%s\n",
		fgRed, rst, dim, templateName, rst, dim, rst, fgRed, errMsg, rst)
}

func PrintVerboseMatch(condition string, matched bool) {
	if matched {
		fmt.Printf("  %s✓%s  matcher [%s] %spassed%s\n",
			bGrn, rst, condition, bGrn, rst)
	} else {
		fmt.Printf("  %s✗%s  matcher [%s] %sfailed%s\n",
			fgRed, rst, condition, fgRed, rst)
	}
}

func PrintVerboseExtracted(name, val string) {
	snip := val
	if len(snip) > 80 {
		snip = snip[:80] + "…"
	}
	fmt.Printf("  %s⇒%s  extract  %s%-14s%s  %s%s%s\n",
		fgMagenta, rst, dim, name, rst, fgYellow, snip, rst)
}

func PrintVerboseOOBPoll(provider, token string) {
	fmt.Printf("  %s⟳%s  OOB polling  %s%s%s  token=%s%s%s\n",
		fgCyan, rst, dim, provider, rst, fgYellow, token, rst)
}

func PrintVerboseOOBResult(hit bool) {
	if hit {
		fmt.Printf("  %s✓%s  OOB callback %sreceived%s\n",
			bGrn, rst, bGrn, rst)
	} else {
		fmt.Printf("  %s✗%s  OOB callback %snot received%s\n",
			fgRed, rst, fgRed, rst)
	}
}

func PrintRequest(method, url string, headers map[string]string, body string) {
	PrintVerboseRequest(method, url, headers, body)
}

func PrintResponse(status int, finalURL string, bodyLen int, elapsed float64) {
	PrintVerboseResponse(status, finalURL, bodyLen, elapsed)
}

func PrintExtracted(name, val string) {
	PrintVerboseExtracted(name, val)
}

func PrintMatchResult(condition string, matched bool) {
	PrintVerboseMatch(condition, matched)
}

// ── JSON output ───────────────────────────────────────────────────────────────

type JSONReport struct {
	ID          string            `json:"id"`
	Template    string            `json:"template"`
	Path        string            `json:"path"`
	Target      string            `json:"target"`
	Severity    string            `json:"severity"`
	CVE         string            `json:"cve,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	MatchedAt   string            `json:"matched_at"`
	Extracted   map[string]string `json:"extracted,omitempty"`
	Author      string            `json:"author,omitempty"`
	Description string            `json:"description,omitempty"`
	Affects     string            `json:"affects,omitempty"`
	References  []string          `json:"references,omitempty"`
	CVSSScore   string            `json:"cvss_score,omitempty"`
	ShodanQuery string            `json:"shodan_query,omitempty"`
	FofaQuery   string            `json:"fofa_query,omitempty"`
}

func SaveJSON(results []*tpl.ScanResult, path string) error {
	var reports []JSONReport
	for _, r := range results {
		if r.Vulnerable {
			reports = append(reports, JSONReport{
				ID:          r.TemplateID,
				Template:    r.TemplateName,
				Path:        r.TemplatePath,
				Target:      r.Target,
				Severity:    r.Severity,
				CVE:         r.CVE,
				Tags:        r.Tags,
				MatchedAt:   r.MatchedAt,
				Extracted:   r.Extracted,
				Author:      r.Author,
				Description: r.Description,
				Affects:     r.Affects,
				References:  r.References,
				CVSSScore:   r.CVSSScore,
				ShodanQuery: r.ShodanQuery,
				FofaQuery:   r.FofaQuery,
			})
		}
	}
	if reports == nil {
		reports = []JSONReport{}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

// ── HTML output (streaming writer) ───────────────────────────────────────────

// HTMLWriter writes an HTML report in real-time as vulnerabilities are found.
// Usage:
//
//	w, err := output.NewHTMLWriter("report.html")
//	w.Append(result)   // called for each vulnerable result
//	w.Close()          // finalises stats and closes the file
type HTMLWriter struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	count    int
	sevCount map[string]int
}

// NewHTMLWriter creates (or truncates) the output file and writes the HTML
// header, styles, and scripts, leaving a placeholder for the top-bar stats.
func NewHTMLWriter(path string) (*HTMLWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := &HTMLWriter{f: f, path: path, sevCount: make(map[string]int)}
	if _, err := f.WriteString(htmlHead() + "<!-- VEIL_TOPBAR_PLACEHOLDER -->\n"); err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

// Append writes one vulnerability row immediately to the report file.
func (w *HTMLWriter) Append(r *tpl.ScanResult) error {
	if !r.Vulnerable {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.count++
	sev := strings.ToLower(r.Severity)
	if sev == "" {
		sev = "info"
	}
	w.sevCount[sev]++
	_, err := w.f.WriteString(buildVulnHTML(r, w.count))
	return err
}

// Close finalises the report: appends </body></html>, then replaces the
// placeholder with the real stats top-bar, and closes the file.
func (w *HTMLWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := w.f.WriteString("\n</body></html>"); err != nil {
		w.f.Close()
		return err
	}
	w.f.Close()

	// Patch placeholder with real stats
	data, err := os.ReadFile(w.path)
	if err != nil {
		return err
	}
	topBar := buildTopBar(w.count, w.sevCount)
	patched := strings.Replace(string(data), "<!-- VEIL_TOPBAR_PLACEHOLDER -->", topBar, 1)
	return os.WriteFile(w.path, []byte(patched), 0644)
}

func buildTopBar(total int, sevCount map[string]int) string {
	var sb strings.Builder
	sb.WriteString(`<div class="top">&nbsp;&nbsp;Veil 漏洞扫描报告&nbsp;&nbsp;&nbsp;`)
	sb.WriteString(fmt.Sprintf(`<span style="font-size:11px;font-weight:normal;color:darkgrey">%s</span>`,
		time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf(`&nbsp;&nbsp;&nbsp;<span style="font-size:12px;color:darkorange">发现漏洞: %d 个</span>`, total))
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c := sevCount[sev]; c > 0 {
			sb.WriteString(fmt.Sprintf(`&nbsp;&nbsp;<span class="%s">%s:%d</span>`, sev, strings.ToUpper(sev), c))
		}
	}
	sb.WriteString(`</div>`)
	return sb.String()
}

// SaveHTML is kept for compatibility (e.g. non-scan/validate modes).
// Live scanning should use NewHTMLWriter instead.
func SaveHTML(results []*tpl.ScanResult, path string) error {
	w, err := NewHTMLWriter(path)
	if err != nil {
		return err
	}
	for _, r := range results {
		if r.Vulnerable {
			_ = w.Append(r)
		}
	}
	return w.Close()
}

func htmlHead() string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Veil 漏洞扫描报告</title>
<style>
html,body,div,span,h1,h2,h3,h4,h5,h6,p,pre,a,code,em,img,small,strong,sub,sup,u,i,
center,dl,dt,dd,ol,ul,li,fieldset,form,label{margin:0;padding:0;border:0;outline:0;
font-size:100%;vertical-align:baseline;background:transparent;}
a{color:#233B46;text-decoration:none;outline:none;}
a:hover{text-decoration:underline}
ol,ul{list-style:none}
table{border-collapse:collapse;border-spacing:0}
xmp{font-family:'Consolas','Menlo','Liberation Mono','DejaVu Sans Mono',monospace;
white-space:pre-wrap;word-wrap:break-word;font-size:11px;line-height:1.5;}
body{color:#233B46;background-color:#C3CAC4;padding:5px;min-width:1220px;overflow:scroll;
font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
font-size:13px;line-height:1.5;}
img{border:none}
.top{width:100%;font-weight:bold;font-size:14px;text-align:left;padding:10px 5px;
background:#4E5B5D;color:#B4C1C3;}
.clr{clear:both;}
.request{float:left;overflow-x:auto;overflow-y:auto;position:relative;background:#223B46;}
.request .toggleR{z-index:999999;position:absolute;padding:0px 10px;background:black;
color:white;top:-5px;left:50%;cursor:pointer;line-height:1.1;}
.w50{width:50%}
.w100{width:100%}
.response{float:left;overflow-x:auto;overflow-y:auto;max-height:800px;position:relative;background:#223B46;}
.response .toggleL{z-index:999999;position:absolute;padding:0px 10px;background:black;
color:white;top:-5px;left:50%;cursor:pointer;line-height:1.1;}
.vuln{text-align:left;font-weight:bold;font-size:12px;}
.security{text-align:left;font-size:12px;}
.url{text-align:left;font-weight:bold;font-size:12px;}
table{table-layout:fixed;width:100%;margin-bottom:10px;}
table td{padding:3px 6px;font-size:12px;}
tbody{display:none;}
thead{cursor:pointer;}
.critical{color:#b454ff;font-weight:bold;}
.high{color:#E74856;font-weight:bold;}
.low{color:#327FBA;font-weight:bold;}
.medium{color:#C19C00;font-weight:bold;}
.info{color:#61D6D6;font-weight:bold;}
.copy-button{display:inline-block;padding:2px 6px;background-color:rgba(92,184,92,0.7);
color:white;border:none;cursor:pointer;transition:background-color 0.3s ease;
font-size:10px;border-radius:3px;margin-left:10px;}
.copy-button:hover{background-color:rgba(92,184,92,0.9);}
.curl-label{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:bold;margin-right:6px;color:white;}
.curl-label.linux{background:#38a169;}
.curl-label.windows{background:#3182ce;}
.curl-box{background:#f8f9fa;padding:5px 8px;margin:4px 0;border-radius:3px;border-left:4px solid #007bff;font-size:10px;line-height:1.4;}
.dork-label{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:bold;margin-right:6px;color:white;flex-shrink:0;}
.dork-shodan{background:#e74c3c;}
.dork-fofa{background:#3498db;}
.dork-code{display:inline-block;background:#f0f0f0;padding:1px 8px;border-radius:3px;font-family:Consolas,monospace;font-size:10px;cursor:pointer;border:1px solid #ddd;transition:background 0.3s ease;user-select:all;margin-right:12px;}
.dork-code:hover{background:#e0e0e0;border-color:#bbb;}
.req-tabs{display:flex;gap:0;background:#3a4a4e;padding:4px 4px 0;}
.req-tab{display:inline-block;padding:4px 14px;font-size:11px;font-weight:bold;color:#aab;cursor:pointer;background:#2a3a3e;border-radius:4px 4px 0 0;border:1px solid #4a5a5e;border-bottom:none;margin-right:2px;transition:background 0.2s;}
.req-tab:hover{background:#4a5a5e;}
.req-tab.active{background:#223B46;color:#DDE2DE;border-color:#223B46;}
.expand-btn{display:inline-block;padding:2px 14px;font-size:10px;font-weight:bold;color:#fff;background:#38a169;border-radius:3px;cursor:pointer;transition:background 0.2s;}
.expand-btn:hover{background:#2f855a;}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>
<script>
function copyXmpContent(that){
  var xmpElement=$(that).siblings('xmp').first();
  if(xmpElement.length===0) xmpElement=$(that).siblings('xmp:visible').first();
  navigator.clipboard.writeText(xmpElement.text()).then(function(){
    $(that).text('Copy Success');
    setTimeout(function(){$(that).text('Copy');},3000);
  },function(err){console.error('Could not copy text: ',err);});
}
function switchTab(groupClass,tabIdx,el){
  $(el).siblings('.req-tab').removeClass('active');
  $(el).addClass('active');
  var panels=$(el).closest('td').find('.'+groupClass);
  panels.hide();
  panels.filter('[data-idx="'+tabIdx+'"]').show();
}
</script>
</head>
<body>
`
}

// buildVulnHTML renders one collapsible table row for a single finding.
// Multi-request templates show each request step as a numbered tab.
// Response bodies longer than 5000 chars are collapsed with an expand button.
func buildVulnHTML(r *tpl.ScanResult, idx int) string {
	var sb strings.Builder

	sev := strings.ToLower(r.Severity)
	if sev == "" {
		sev = "info"
	}

	matchedAt := r.MatchedAt
	if matchedAt == "" {
		matchedAt = r.Target
	}

	// Strip to host for the compact column
	hostLabel := htmlHostOnly(matchedAt)

	templateName := r.TemplateName
	if templateName == "" {
		templateName = r.TemplatePath
	}

	timestamp := time.Now().Format("2006/01/02 15:04:05")

	// Table header (click to expand tbody) — 4 columns: idx+id, severity, url, timestamp
	sb.WriteString(fmt.Sprintf(`
<table>
<thead onclick="$(this).next('tbody').toggle()" style="background:#DDE2DE">
  <td class="vuln">%03d&nbsp;&nbsp;%s</td>
  <td class="security %s">%s</td>
  <td class="url">%s</td>
  <td style="text-align:right;font-size:12px;color:#666;white-space:nowrap;width:140px;">%s</td>
</thead><tbody><tr>
  <td colspan="4">
    <b>模板 ID:</b> %s&nbsp;&nbsp;&nbsp;&nbsp;<b>模板名:</b> %s&nbsp;&nbsp;&nbsp;&nbsp;<b>作者:</b> %s&nbsp;&nbsp;&nbsp;&nbsp;<b>严重性:</b> <span class="%s">%s</span>`,
		idx,
		htmlEsc(r.TemplateID),
		sev,
		strings.ToUpper(sev),
		htmlEsc(hostLabel),
		timestamp,
		htmlEsc(r.TemplateID),
		htmlEsc(templateName),
		htmlEsc(r.Author),
		sev,
		strings.ToUpper(sev),
	))

	// Description
	if r.Description != "" {
		sb.WriteString(fmt.Sprintf(`<br/><b>描述:</b> %s`, htmlEsc(r.Description)))
	}

	// Affects
	if r.Affects != "" {
		sb.WriteString(fmt.Sprintf(`<br/><b>影响:</b> %s`, htmlEsc(r.Affects)))
	}

	if r.CVE != "" {
		sb.WriteString(fmt.Sprintf(`<br/><b>CVE:</b> %s`, htmlEsc(r.CVE)))
	}
	if r.CVSSScore != "" {
		sb.WriteString(fmt.Sprintf(`&nbsp;&nbsp;&nbsp;&nbsp;<b>CVSS:</b> %s`, htmlEsc(r.CVSSScore)))
	}
	if len(r.Tags) > 0 {
		sb.WriteString(fmt.Sprintf(`<br/><b>Tags:</b> %s`, htmlEsc(strings.Join(r.Tags, ", "))))
	}

	// References
	if len(r.References) > 0 {
		sb.WriteString(`<br/><b>参考链接:</b><br/>`)
		for _, ref := range r.References {
			sb.WriteString(fmt.Sprintf(`&nbsp;&nbsp;<a href="%s" target="_blank">%s</a><br/>`, htmlEsc(ref), htmlEsc(ref)))
		}
	}

	// Shodan / FOFA queries — single inline row, clickable code blocks
	if r.ShodanQuery != "" || r.FofaQuery != "" {
		sb.WriteString(`<br/><b>空间测绘:</b>&nbsp;&nbsp;`)
		if r.ShodanQuery != "" {
			sb.WriteString(fmt.Sprintf(`<span class="dork-label dork-shodan">Shodan</span><code class="dork-code" onclick="navigator.clipboard.writeText(this.innerText).then(function(){var el=event.target;el.style.background='#d4edda';setTimeout(function(){el.style.background='';},800);});" title="点击复制">%s</code>`, htmlEsc(r.ShodanQuery)))
		}
		if r.FofaQuery != "" {
			sb.WriteString(fmt.Sprintf(`<span class="dork-label dork-fofa">FOFA</span><code class="dork-code" onclick="navigator.clipboard.writeText(this.innerText).then(function(){var el=event.target;el.style.background='#d4edda';setTimeout(function(){el.style.background='';},800);});" title="点击复制">%s</code>`, htmlEsc(r.FofaQuery)))
		}
	}

	// Matched variable values (e.g. which username/path triggered the match)
	if len(r.MatchedVars) > 0 {
		sb.WriteString(`<br/><b>命中变量:</b>&nbsp;&nbsp;`)
		for k, v := range r.MatchedVars {
			snip := v
			if len(snip) > 120 {
				snip = snip[:120] + "…"
			}
			sb.WriteString(fmt.Sprintf(`<code class="dork-code" style="border-left:4px solid #38a169;">%s = %s</code>&nbsp;&nbsp;`, htmlEsc(k), htmlEsc(snip)))
		}
	}

	sb.WriteString(`</td></tr>`)

	// Full matched URL row
	sb.WriteString(fmt.Sprintf(`<tr><td colspan="4" style="border-top:1px solid #60786F">
  <a href="%s" target="_blank">%s</a>
</td></tr>`, htmlEsc(matchedAt), htmlEsc(matchedAt)))

	// Extracted data
	if len(r.Extracted) > 0 {
		sb.WriteString(`<tr><td colspan="4"><b>提取数据:</b><br/>`)
		for k, v := range r.Extracted {
			snip := v
			if len(snip) > 200 {
				snip = snip[:200] + "…"
			}
			sb.WriteString(fmt.Sprintf("&nbsp;&nbsp;<b>%s</b>: %s<br/>", htmlEsc(k), htmlEscLinkify(snip)))
		}
		sb.WriteString(`</td></tr>`)
	}

	numInteractions := len(r.Interactions)

	// CURL commands — only one consolidated block with all interactions
	hasCurl := false
	for _, interaction := range r.Interactions {
		if interaction.CURLCommand != "" {
			hasCurl = true
			break
		}
	}
	if hasCurl {
		sb.WriteString(`<tr><td colspan="4"><b>重现命令:</b><br/>`)
		for i, interaction := range r.Interactions {
			if interaction.CURLCommand == "" {
				continue
			}
			linuxCmd := interaction.CURLCommand
			windowsCmd := curlToWindows(linuxCmd)

			stepLabel := ""
			if numInteractions > 1 {
				stepLabel = fmt.Sprintf(`<span style="font-size:9px;color:#666;font-weight:bold;">Step %d/%d</span>&nbsp;&nbsp;`, i+1, numInteractions)
			}
			sb.WriteString(`<div class="curl-box">`)
			sb.WriteString(stepLabel)
			sb.WriteString(fmt.Sprintf(`<div style="margin-bottom:3px;"><span class="curl-label linux">Linux</span><code style="font-family:Consolas,monospace;font-size:9px;word-break:break-all;cursor:pointer;" onclick="navigator.clipboard.writeText(this.innerText).then(function(){var el=event.target;el.style.background='#d4edda';setTimeout(function(){el.style.background='';},800);});" title="点击复制">%s</code></div>`, htmlEsc(linuxCmd)))
			sb.WriteString(fmt.Sprintf(`<div><span class="curl-label windows">Windows</span><code style="font-family:Consolas,monospace;font-size:9px;word-break:break-all;cursor:pointer;" onclick="navigator.clipboard.writeText(this.innerText).then(function(){var el=event.target;el.style.background='#d4edda';setTimeout(function(){el.style.background='';},800);});" title="点击复制">%s</code></div>`, htmlEsc(windowsCmd)))
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`</td></tr>`)
	}

	// Request / Response pairs with tabs for multi-request templates
	if numInteractions > 1 {
		// Multi-request: render tab bar + tab panels
		tabGroupID := fmt.Sprintf("tabs_%d", idx)

		// Tab bar
		sb.WriteString(`<tr><td colspan="4" style="padding:0;">`)
		sb.WriteString(`<div class="req-tabs">`)
		for i := range r.Interactions {
			activeClass := ""
			if i == 0 {
				activeClass = " active"
			}
			sb.WriteString(fmt.Sprintf(`<span class="req-tab%s" onclick="switchTab('%s',%d,this)">请求 #%d</span>`,
				activeClass, tabGroupID, i, i+1))
		}
		sb.WriteString(`</div>`)

		// Tab panels
		for i, interaction := range r.Interactions {
			display := "none"
			if i == 0 {
				display = "block"
			}
			sb.WriteString(fmt.Sprintf(`<div class="req-panel %s" data-idx="%d" style="display:%s;">`,
				tabGroupID, i, display))
			sb.WriteString(buildInteractionHTML(interaction, idx, i))
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`</td></tr>`)
	} else if numInteractions == 1 {
		// Single request: render directly (no tabs)
		sb.WriteString(`<tr><td colspan="4" style="padding:0;">`)
		sb.WriteString(buildInteractionHTML(r.Interactions[0], idx, 0))
		sb.WriteString(`</td></tr>`)
	}

	sb.WriteString(`</tbody></table>`)
	return sb.String()
}

// responseBodyLimit is the character threshold above which the response body
// is initially collapsed in the HTML report.
const responseBodyLimit = 5000

// buildInteractionHTML renders one request/response pair.
// Response bodies exceeding responseBodyLimit are truncated with an expand button.
func buildInteractionHTML(interaction tpl.RequestResponse, vulnIdx, reqIdx int) string {
	if interaction.Request == "" && interaction.Response == "" {
		return ""
	}
	var sb strings.Builder

	sb.WriteString(`<div style="background:#223B46;color:#DDE2DE;padding:2px 0;overflow:hidden;">
	<div class="clr">`)

	if interaction.Request != "" {
		sb.WriteString(`
		<div class="request w50">
		<div class="toggleR" onclick="$(this).parent().next('.response').toggle();if($(this).text()=='→'){$(this).text('←');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('→');$(this).css('background','black');$(this).parent().removeClass('w100').addClass('w50')}">→</div>
		<div class="copy-button" onclick="copyXmpContent(this);">Copy</div>
<xmp>`)
		sb.WriteString(xmpSafe(interaction.Request))
		sb.WriteString(`</xmp>
		</div>`)
	}

	if interaction.Response != "" {
		resp := interaction.Response
		needsCollapse := len(resp) > responseBodyLimit

		sb.WriteString(`
		<div class="response w50">
		<div class="toggleL" onclick="$(this).parent().prev('.request').toggle();if($(this).text()=='←'){$(this).text('→');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('←');$(this).css('background','black');$(this).parent().removeClass('w100').addClass('w50')}">←</div>`)

		if needsCollapse {
			truncID := fmt.Sprintf("resp_%d_%d", vulnIdx, reqIdx)
			// Show truncated version by default
			sb.WriteString(fmt.Sprintf(`
<xmp id="%s_short">%s

... [响应内容过长，已折叠 %d 字符] ...</xmp>
<xmp id="%s_full" style="display:none;">%s</xmp>
<div style="text-align:center;padding:4px;background:#223B46;">
  <span class="expand-btn" onclick="var s=document.getElementById('%s_short');var f=document.getElementById('%s_full');if(s.style.display!='none'){s.style.display='none';f.style.display='block';this.innerText='收起';}else{s.style.display='block';f.style.display='none';this.innerText='展开全部';}">展开全部</span>
</div>`,
				truncID, xmpSafe(resp[:responseBodyLimit]),
				len(resp),
				truncID, xmpSafe(resp),
				truncID, truncID))
		} else {
			sb.WriteString(`
<xmp>`)
			sb.WriteString(xmpSafe(resp))
			sb.WriteString(`</xmp>`)
		}
		sb.WriteString(`
		</div>`)
	}

	sb.WriteString(`
	</div>
	</div>`)
	return sb.String()
}

// xmpSafe escapes </xmp> inside xmp tags to prevent premature closing.
func xmpSafe(s string) string {
	if strings.Contains(strings.ToLower(s), "</xmp>") {
		s = strings.ReplaceAll(s, "</xmp>", "&lt;/xmp&gt;")
		s = strings.ReplaceAll(s, "</XMP>", "&lt;/XMP&gt;")
	}
	return s
}

// curlToWindows converts a Linux curl command to Windows cmd format.
func curlToWindows(curlCmd string) string {
	if curlCmd == "" {
		return ""
	}
	winCmd := strings.ReplaceAll(curlCmd, "'", "\"")
	winCmd = strings.ReplaceAll(winCmd, " \\\n", " ^\n")
	winCmd = strings.ReplaceAll(winCmd, "\\\n", "^\n")
	return winCmd
}

// ── HTML helpers ──────────────────────────────────────────────────────────────

func htmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

func htmlEscLinkify(s string) string {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return fmt.Sprintf(`<a href="%s" target="_blank">%s</a>`, htmlEsc(s), htmlEsc(s))
	}
	return htmlEsc(s)
}

// htmlHostOnly strips path/query from a URL, returning scheme://host.
func htmlHostOnly(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rest := rawURL[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			return rawURL[:i+3] + rest[:j]
		}
		return rawURL[:i+3] + rest
	}
	return rawURL
}