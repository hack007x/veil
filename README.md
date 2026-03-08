<div align="center">

<img width="120" height="120" alt="Veil icon" src="https://github.com/user-attachments/assets/bd77c292-f442-4f87-9355-cd3a2e0c1597" />

「Mirrored Flowers and Reflected Moon — where illusion and reality give rise to each other.」

See beyond appearances to grasp the essence · Turn the intangible into the tangible to safeguard security

<br>

**Template-based vulnerability scanner**

Veil is a fast, template-driven HTTP vulnerability scanner written in Go.<br>
It executes `.poc` template files against one or more targets,<br>
evaluates flexible matcher expressions against responses,<br>
extracts evidence from response bodies,<br>
and outputs clean, colour-coded results.

<br>

[<code>English</code>](https://github.com/hack007x/veil/blob/main/README_EN.md) • 
[<code>中文</code>](https://github.com/hack007x/veil/blob/main/README_ZH.md) • 
[<code>Write a proof-of-concept (PoC) using custom syntax.</code>](https://github.com/hack007x/veil/wiki/veil-Poc-%E8%AF%AD%E6%B3%95%E6%80%BB%E8%A7%88v1.2.0) • 
[<code>POC</code>](https://github.com/hack007x/veil_poc)

</div>

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Basic Scanning](#basic-scanning)
  - [Filtering](#filtering)
  - [Output](#output)
  - [Network Configuration](#network-configuration)
  - [Template Management](#template-management)
- [Template Syntax](#template-syntax)
  - [Basic Structure](#basic-structure)
  - [Metadata Fields](#metadata-fields)
  - [Variables](#variables)
  - [Matchers](#matchers)
  - [Extractors](#extractors)
  - [Multi-Request Chains](#multi-request-chains)
  - [Attack Modes](#attack-modes)
  - [OOB Verification](#oob-verification)
  - [Built-in Functions](#built-in-functions)
  - [Built-in Variables](#built-in-variables)
- [CLI Reference](#cli-reference)
- [Disclaimer](#disclaimer)

---

## Features

- **Custom Template Syntax** — Clean `.poc` file format with metadata, variables, multi-request chains, matchers, and extractors
- **Multi-Request Chains** — Separate multiple requests with `---`; extracted values are automatically passed to subsequent steps
- **Flexible Matchers** — Status code comparison, body matching (contains/regex/starts_with/ends_with), header matching, logical operators (&&/||/not)
- **Value Extraction** — Extract data from responses via regex, JSON path, or key-value patterns
- **OOB Callback Verification** — Built-in support for ceye.io / interactsh / dnslog.cn / dig.pm; automatically detects OOB references in templates
- **Attack Modes** — Sniper (iterate one variable at a time) / Pitchfork (lock-step) / Clusterbomb (cartesian product)
- **Multi-Value Variables** — Pipe-separated `val1 | val2 | val3` or loaded from files via `@file(wordlist.txt)`
- **Template Functions** — 22 built-in functions: base64, URL encoding, MD5/SHA hashing, string operations, random generation, and more
- **Liveness Probing** — Automatic target probing before scanning, HTTPS preferred
- **Template Validation** — Two-pass static analysis (raw text lint + AST validation) to catch syntax errors and potential issues
- **HTML / JSON Reports** — HTML reports are streamed in real-time with request/response panels, curl reproduction commands, and multi-request tabs
- **Concurrent Scanning** — Goroutine pool with configurable concurrency
- **POC Management** — `-pl` to list all POCs, `-pv` to view details by ID

---

## Installation

```bash
# Clone the repository
git clone https://github.com/hack007x/veil.git
cd veil

# Build
go build -o veil .

# Place POC files in the veil_poc/ directory (default search path)
mkdir -p veil_poc
```

**Requirements**: Go 1.21+

---

## Quick Start

### Basic Scanning

```bash
# Scan a single target
./veil -u https://example.com

# Scan multiple targets
./veil -u https://a.com -u https://b.com

# Load targets from file
./veil -l targets.txt

# Specify a template
./veil -u https://example.com -t poc/cve-2023-xxxx.poc

# Specify a template directory
./veil -u https://example.com -T my_pocs/
```

### Filtering

```bash
# By severity
./veil -u https://example.com -severity critical,high

# By tags
./veil -u https://example.com -tags rce,sqli

# By CVE
./veil -u https://example.com -cve CVE-2023-5561

# By template ID
./veil -u https://example.com -id CVE-2023-5561
```

### Output

```bash
# Verbose mode (show request/response/matching details)
./veil -u https://example.com -v

# Save JSON report
./veil -u https://example.com -o results.json

# Save HTML report
./veil -u https://example.com -o report.html
```

### Network Configuration

```bash
# Set timeout
./veil -u https://example.com -timeout 15

# Use proxy
./veil -u https://example.com -proxy http://127.0.0.1:8080

# Skip SSL verification
./veil -u https://example.com -no-verify-ssl

# Disable redirects
./veil -u https://example.com -no-follow-redirects
```

### Template Management

```bash
# List all POCs
./veil -pl

# View a specific POC by ID
./veil -pv CVE-2023-5561

# Validate templates without scanning
./veil -validate -T my_pocs/
```

---

## Template Syntax

`.poc` files are a declarative template format for describing vulnerability detection logic.

### Basic Structure

```
## id: CVE-2023-XXXX
## name: Vulnerability Name
## author: researcher
## severity: high
## description: Vulnerability description
## cve: CVE-2023-XXXX
## tags: rce, injection
## reference: https://example.com/advisory

GET /vulnerable/path?param=value
User-Agent: {{random_ua}}

#@ matcher: status_code == 200 && body contains "vulnerable"
```

### Metadata Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | ✓ | Unique identifier |
| `name` | ✓ | Vulnerability name |
| `author` | ✓ | Author |
| `severity` | ✓ | critical / high / medium / low / info |
| `cve` | | CVE identifier |
| `tags` | | Comma-separated tags |
| `description` | | Vulnerability description |
| `affects` | | Affected software/versions |
| `reference` | | Reference links (repeatable) |
| `cvss-score` | | CVSS score (0.0-10.0) |
| `shodan-query` | | Shodan search dork |
| `fofa-query` | | FOFA search dork |

### Variables

```
#$ payload = test_value
#$ paths = /api/v1 | /api/v2 | /api/v3
#$ usernames = @file(users.txt)
```

### Matchers

```
#@ matcher: status_code == 200
#@ matcher: body contains "success"
#@ matcher: body matches /version[:\s]+(\d+\.\d+)/
#@ matcher: header["Content-Type"] contains "json"
#@ matcher: status_code == 200 && body contains "admin"
#@ matcher: (body contains "root" || body contains "admin") && status_code == 200
#@ condition: and
```

### Extractors

```
#> extract: name=token, regex=/csrf_token[=:]([a-f0-9]+)/, group=1
#> extract: name=version, json=$.data.version
#> extract: name=session, kval=JSESSIONID, from=headers
#> extract: name=internal_val, regex=/id=(\d+)/, internal=true
```

### Multi-Request Chains

```
GET /api/login
#@ matcher: status_code == 200
#> extract: name=token, regex=/token":"([^"]+)/
---
POST /api/action
Content-Type: application/json

{"token": "{{token}}", "cmd": "whoami"}
#@ matcher: body contains "success"
```

### Attack Modes

```
#$ username = admin | root | test
#$ password = 123456 | admin | password
#@ attack: clusterbomb
```

### OOB Verification

```
GET /api/ssrf?url=http://{{oob_domain}}/probe
#@ oob: dns
#@ matcher: oob_received == true
```

### Built-in Functions

| Function | Example | Description |
|----------|---------|-------------|
| `base64(x)` | `{{base64(payload)}}` | Base64 encode |
| `url_encode(x)` | `{{url_encode(param)}}` | URL encode |
| `md5(x)` | `{{md5(password)}}` | MD5 hash |
| `sha256(x)` | `{{sha256(data)}}` | SHA-256 hash |
| `to_lower(x)` | `{{to_lower(Name)}}` | Lowercase |
| `random_str(n)` | `{{random_str(8)}}` | Random string |
| `random_int(a,b)` | `{{random_int(1,100)}}` | Random integer |
| `replace(x,a,b)` | `{{replace(str,old,new)}}` | String replace |

Nested calls are supported: `{{base64({{payload}})}}`

### Built-in Variables

| Variable | Description |
|----------|-------------|
| `{{Hostname}}` | Target hostname |
| `{{Host}}` | hostname:port |
| `{{BaseURL}}` | scheme://host:port |
| `{{Scheme}}` | http or https |
| `{{Port}}` | Port number |
| `{{Path}}` | URL path |
| `{{random_ua}}` | Random User-Agent |
| `{{timestamp}}` | Current Unix timestamp |
| `{{oob_domain}}` | OOB callback domain |
| `{{oob_url}}` | OOB callback URL |

---

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-u URL` | Target URL (repeatable) | |
| `-l FILE` | Target list file | |
| `-t PATH` | Template path (repeatable) | |
| `-T DIR` | Template directory | `./veil_poc/` |
| `-id VALUE` | Filter by ID | |
| `-severity VALUE` | Filter by severity | |
| `-tags VALUE` | Filter by tag | |
| `-cve VALUE` | Filter by CVE | |
| `-timeout N` | Timeout in seconds | `10` |
| `-proxy URL` | Proxy URL | |
| `-no-verify-ssl` | Skip TLS verification | `false` |
| `-no-follow-redirects` | Disable redirects | `false` |
| `-c N` | Concurrency | `10` |
| `-v` | Verbose mode | `false` |
| `-o FILE` | Output file (.json/.html) | |
| `-stats` | Print statistics | `false` |
| `-validate` | Validate templates and exit | `false` |
| `-pl` | List all POCs | |
| `-pv ID` | View POC by ID | |

---

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Do not use this tool against systems without explicit permission. By using this tool, you agree to take full responsibility for your actions.
