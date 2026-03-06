// Package oob implements out-of-band (OOB) callback verification via third-party
// DNSLog platforms such as ceye.io, dnslog.cn, interactsh, etc.
//
// OOB provider credentials are hardcoded below (ceye.io).
// Fallback order: ceye.io → interactsh(oast.pro) → dnslog.cn → dig.pm
package oob

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

// debug controls OOB diagnostic output.
// Set to true only when troubleshooting OOB connectivity issues.
const debug = false

// ── Hardcoded OOB configuration ───────────────────────────────────────────────
// Edit these values to change your ceye.io credentials.
// If ceyeDomain / ceyeToken are empty, ceye.io is skipped and
// the tool falls back to interactsh → dnslog.cn → dig.pm.
const (
	ceyeDomain       = "kvdu84.ceye.io"
	ceyeToken        = "57a3e49fece0519c01fe693be8671489"
	interactshServer = "oast.pro" // change to oast.live / oast.site etc. if needed
)

// ── Provider interface ─────────────────────────────────────────────────────────

type Provider interface {
	Name() string
	Init() bool
	BaseDomain() string
	CheckCallback(token string) (bool, error)
}

func dbgf(format string, args ...interface{}) {
	if debug {
		fmt.Printf("  \033[2;96m[OOB]\033[0m  "+format+"\n", args...)
	}
}

// ── Manager ────────────────────────────────────────────────────────────────────

type Manager struct {
	mu       sync.Mutex
	provider Provider
	inited   bool
}

// NewManager creates a Manager.
// The verbose parameter is kept for API compatibility; debug output is
// controlled by the package-level `debug` constant.
func NewManager(_ bool) *Manager {
	m := &Manager{}
	m.init()
	return m
}

func (m *Manager) init() {
	var providers []Provider

	if ceyeDomain != "" && ceyeToken != "" {
		providers = append(providers, &CeyeProvider{
			apiToken: ceyeToken,
			domain:   ceyeDomain,
		})
		dbgf("使用内置 ceye.io 配置 (domain=%s)", ceyeDomain)
	}

	providers = append(providers, &InteractshProvider{server: interactshServer})
	providers = append(providers, &DnslogCNProvider{})
	providers = append(providers, &DigPMProvider{})

	for _, p := range providers {
		dbgf("尝试连接 %s ...", p.Name())
		if p.Init() {
			m.provider = p
			m.inited = true
			dbgf("%s 连接成功, 域名: %s", p.Name(), p.BaseDomain())
			return
		}
		dbgf("%s 不可用, 尝试下一个", p.Name())
	}
}

func (m *Manager) Available() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inited && m.provider != nil
}

func (m *Manager) ProviderName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.provider == nil {
		return ""
	}
	return m.provider.Name()
}

func (m *Manager) GenerateToken() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func (m *Manager) Domain(token string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.provider == nil {
		return ""
	}
	return token + "." + m.provider.BaseDomain()
}

func (m *Manager) BaseDomain() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.provider == nil {
		return ""
	}
	return m.provider.BaseDomain()
}

// Poll checks whether a callback was received for the given token.
//
// Wait strategy:
//
//	[0~8s]   initial wait — let the target server complete its request
//	[8~68s]  poll every 5s up to 12 times
func (m *Manager) Poll(token string, _ time.Duration) bool {
	m.mu.Lock()
	p := m.provider
	m.mu.Unlock()
	if p == nil {
		return false
	}

	time.Sleep(8 * time.Second)

	for attempt := 1; attempt <= 12; attempt++ {
		dbgf("第 %d 次查询 (token=%s)", attempt, token)
		hit, err := p.CheckCallback(token)
		if err != nil {
			dbgf("查询出错: %v", err)
		}
		if hit {
			return true
		}
		if attempt < 12 {
			time.Sleep(5 * time.Second)
		}
	}
	return false
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

func newHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout: 15 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

func httpGet(client *http.Client, rawURL string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func httpPost(client *http.Client, rawURL string, payload []byte) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

// ═══════════════════════════════════════════════════════════════════════════════
// Provider: ceye.io
//
// ceye.io API:
//   GET http://api.ceye.io/v1/records?token=TOKEN&type=TYPE&filter=FILTER
//   type:   dns      — DNS resolution records
//           request  — HTTP request records  (curl/wget hits go here!)
//   filter: prefix match, max 20 chars
//
// We query BOTH types because:
//   - curl on the target triggers an HTTP request record (type=request)
//   - DNS resolution may or may not be recorded depending on the target network
// ═══════════════════════════════════════════════════════════════════════════════

type CeyeProvider struct {
	apiToken string
	domain   string
	client   *http.Client
}

func (c *CeyeProvider) Name() string { return "ceye.io" }

func (c *CeyeProvider) Init() bool {
	if c.apiToken == "" || c.domain == "" {
		return false
	}
	c.client = newHTTPClient()
	// Verify token works by querying dns records (empty result is fine, non-200 means bad token)
	url := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=init", c.apiToken)
	_, status, err := httpGet(c.client, url)
	if err != nil {
		dbgf("ceye.io 连接失败: %v", err)
		return false
	}
	return status == 200
}

func (c *CeyeProvider) BaseDomain() string { return c.domain }

// CheckCallback queries both dns and request record types.
// A curl/wget SSRF will appear in type=request; DNS-only payloads in type=dns.
func (c *CeyeProvider) CheckCallback(token string) (bool, error) {
	// ceye filter max length is 20 — token is 12 chars, safe.
	for _, recType := range []string{"dns", "http"} {
		url := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=%s&filter=%s",
			c.apiToken, recType, token)
		body, status, err := httpGet(c.client, url)
		if err != nil {
			dbgf("ceye.io [%s] 查询失败: %v", recType, err)
			continue
		}
		if status != 200 {
			dbgf("ceye.io [%s] 返回 %d", recType, status)
			continue
		}
		if debug {
			snippet := string(body)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			dbgf("ceye.io [%s] 响应: %s", recType, snippet)
		}
		// ceye response: {"meta": {"code": 200, "message": "OK"}, "data": [...]}
		var result struct {
			Meta struct {
				Code int `json:"code"`
			} `json:"meta"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			dbgf("ceye.io JSON 解析失败: %v", err)
			continue
		}
		dataStr := strings.TrimSpace(string(result.Data))
		if dataStr != "" && dataStr != "null" && dataStr != "[]" {
			dbgf("ceye.io [%s] 命中! data=%s", recType, dataStr)
			return true, nil
		}
	}
	return false, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// Provider: interactsh (projectdiscovery)
// Public instances: oast.pro / oast.live / oast.site / oast.online / oast.fun
// ═══════════════════════════════════════════════════════════════════════════════

type InteractshProvider struct {
	server    string
	domain    string
	correlID  string
	secretKey string
	client    *http.Client
}

func (p *InteractshProvider) Name() string { return "interactsh(" + p.server + ")" }

func (p *InteractshProvider) Init() bool {
	if p.server == "" {
		p.server = "oast.pro"
	}
	p.client = newHTTPClient()

	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	p.correlID = string(b)
	p.secretKey = p.correlID

	payload, _ := json.Marshal(map[string]string{
		"correlation-id": p.correlID,
		"secret-key":     p.secretKey,
	})
	body, status, err := httpPost(p.client, fmt.Sprintf("https://%s/register", p.server), payload)
	if err != nil {
		dbgf("interactsh(%s) 注册失败: %v", p.server, err)
		return false
	}
	if status != 200 {
		dbgf("interactsh(%s) 注册状态码: %d body: %s", p.server, status, string(body))
		return false
	}
	p.domain = p.correlID + "." + p.server
	dbgf("interactsh 域名: %s", p.domain)
	return true
}

func (p *InteractshProvider) BaseDomain() string { return p.domain }

func (p *InteractshProvider) CheckCallback(token string) (bool, error) {
	body, status, err := httpGet(p.client,
		fmt.Sprintf("https://%s/poll?id=%s&secret=%s", p.server, p.correlID, p.secretKey))
	if err != nil {
		return false, fmt.Errorf("interactsh poll: %w", err)
	}
	if status != 200 {
		return false, fmt.Errorf("interactsh poll returned %d", status)
	}
	content := strings.TrimSpace(string(body))
	dbgf("interactsh 记录: %.300s", content)
	if content == "" || content == "null" || content == "{}" {
		return false, nil
	}
	return strings.Contains(strings.ToLower(content), strings.ToLower(token)), nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// Provider: dnslog.cn
// ═══════════════════════════════════════════════════════════════════════════════

type DnslogCNProvider struct {
	domain string
	client *http.Client
}

func (d *DnslogCNProvider) Name() string { return "dnslog.cn" }

func (d *DnslogCNProvider) Init() bool {
	d.client = newHTTPClient()
	body, status, err := httpGet(d.client, "http://www.dnslog.cn/getdomain.php")
	if err != nil || status != 200 {
		dbgf("dnslog.cn 连接失败: status=%d err=%v", status, err)
		return false
	}
	domain := strings.TrimSpace(string(body))
	if domain == "" || !strings.Contains(domain, ".") {
		dbgf("dnslog.cn 返回无效域名: %q", domain)
		return false
	}
	d.domain = domain
	_, recStatus, recErr := httpGet(d.client, "http://www.dnslog.cn/getrecords.php")
	if recErr != nil || recStatus != 200 {
		dbgf("dnslog.cn session 验证失败: status=%d err=%v", recStatus, recErr)
		return false
	}
	dbgf("dnslog.cn 域名: %s", domain)
	return true
}

func (d *DnslogCNProvider) BaseDomain() string { return d.domain }

func (d *DnslogCNProvider) CheckCallback(token string) (bool, error) {
	body, status, err := httpGet(d.client, "http://www.dnslog.cn/getrecords.php")
	if err != nil {
		return false, fmt.Errorf("dnslog.cn: %w", err)
	}
	if status != 200 {
		return false, fmt.Errorf("dnslog.cn returned %d", status)
	}
	content := strings.TrimSpace(string(body))
	dbgf("dnslog.cn 记录: %.300s", content)
	if content == "[]" || content == "" || content == "null" {
		return false, nil
	}
	return strings.Contains(strings.ToLower(content), strings.ToLower(token)), nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// Provider: dig.pm
// ═══════════════════════════════════════════════════════════════════════════════

type DigPMProvider struct {
	domain string
	client *http.Client
}

func (d *DigPMProvider) Name() string { return "dig.pm" }

func (d *DigPMProvider) Init() bool {
	d.client = newHTTPClient()
	body, status, err := httpGet(d.client, "https://dig.pm/new_gen")
	if err != nil || status != 200 {
		dbgf("dig.pm 连接失败: status=%d err=%v", status, err)
		return false
	}
	domain := strings.TrimSpace(string(body))
	if domain == "" || !strings.Contains(domain, ".") {
		return false
	}
	d.domain = domain
	return true
}

func (d *DigPMProvider) BaseDomain() string { return d.domain }

func (d *DigPMProvider) CheckCallback(token string) (bool, error) {
	body, status, err := httpGet(d.client, fmt.Sprintf("https://dig.pm/get_results?domain=%s", d.domain))
	if err != nil {
		return false, err
	}
	if status != 200 {
		return false, fmt.Errorf("dig.pm returned %d", status)
	}
	content := strings.TrimSpace(string(body))
	dbgf("dig.pm 记录: %.300s", content)
	if content == "[]" || content == "" || content == "null" {
		return false, nil
	}
	return strings.Contains(strings.ToLower(content), strings.ToLower(token)), nil
}