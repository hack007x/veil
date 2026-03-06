<div align="center">
  
<img width="120" height="120" alt="Veil icon" src="https://github.com/user-attachments/assets/bd77c292-f442-4f87-9355-cd3a2e0c1597" />

「镜花水月，虚实相生」

透过现象看本质 · 化虚为实守安全

<br>

**基于模板的漏洞扫描器**

Veil 是一款使用 `.poc` 模板文件驱动的 HTTP 漏洞扫描器，使用 Go 编写，<br>
支持高并发扫描、灵活的匹配规则、变量提取与 OOB 回调检测。

<br>

[<code>English</code>](https://github.com/hack007x/veil/blob/main/README_EN.md) • 
[<code>中文</code>](https://github.com/hack007x/veil/blob/main/README_ZH.md) • 
[<code>veil自定义语法编写(PoC)</code>](https://github.com/hack007x/veil/wiki/veil-Poc-%E8%AF%AD%E6%B3%95%E6%80%BB%E8%A7%88)

</div>

## 目录

- [特性](#特性)
- [安装](#安装)
- [快速开始](#快速开始)
  - [基本扫描](#基本扫描)
  - [筛选](#筛选)
  - [输出](#输出)
  - [网络配置](#网络配置)
  - [模板管理](#模板管理)
- [模板语法](#模板语法)
  - [基本结构](#基本结构)
  - [元数据字段](#元数据字段)
  - [变量](#变量)
  - [匹配器](#匹配器)
  - [提取器](#提取器)
  - [多请求链](#多请求链)
  - [攻击模式](#攻击模式)
  - [OOB 验证](#oob-验证)
  - [内置函数](#内置函数)
  - [内置变量](#内置变量)
- [命令行参数](#命令行参数)
- [许可证](#许可证)

---

## 特性

- **自定义模板语法** — 简洁的 `.poc` 文件格式，支持元数据、变量、多请求链、匹配器和提取器
- **多请求链** — 用 `---` 分隔多个请求，提取值自动传递给下一步
- **灵活的匹配器** — 支持状态码比较、正文匹配（contains/regex/starts_with/ends_with）、Header 匹配、逻辑组合（&&/||/not）
- **值提取** — 通过正则、JSON 路径、键值对从响应中提取数据
- **OOB 回调验证** — 内置 ceye.io / interactsh / dnslog.cn / dig.pm 多平台回调检测，自动识别模板中的 OOB 引用
- **攻击模式** — Sniper（逐变量遍历）/ Pitchfork（同步推进）/ Clusterbomb（笛卡尔积）
- **多值变量** — 管道分隔 `val1 | val2 | val3` 或从文件加载 `@file(wordlist.txt)`
- **模板函数** — 22 个内置函数：base64、URL 编码、MD5/SHA 哈希、字符串操作、随机生成等
- **存活探测** — 扫描前自动探测目标存活，HTTPS 优先
- **模板校验** — 两遍静态分析（原始文本 lint + AST 验证），捕获语法错误和潜在问题
- **HTML / JSON 报告** — HTML 实时流式写入，支持请求/响应面板、curl 复现命令、多请求标签页
- **并发扫描** — goroutine 池，可配置并发数
- **POC 管理** — `-pl` 列出所有 POC，`-pv` 按 ID 查看详情

---

## 安装

```bash
# 克隆项目
git clone https://github.com/hack007x/veil.git
cd veil

# 编译
go build -o veil .

# 将 POC 文件放在 veil_poc/ 目录下（默认搜索路径）
mkdir -p veil_poc
```

**环境要求**: Go 1.21+

---

## 快速开始

### 基本扫描

```bash
# 扫描单个目标
./veil -u https://example.com

# 扫描多个目标
./veil -u https://a.com -u https://b.com

# 从文件加载目标
./veil -l targets.txt

# 指定模板
./veil -u https://example.com -t poc/cve-2023-xxxx.poc

# 指定模板目录
./veil -u https://example.com -T my_pocs/
```

### 筛选

```bash
# 按严重性
./veil -u https://example.com -severity critical,high

# 按标签
./veil -u https://example.com -tags rce,sqli

# 按 CVE
./veil -u https://example.com -cve CVE-2023-5561

# 按模板 ID
./veil -u https://example.com -id CVE-2023-5561
```

### 输出

```bash
# 详细模式（显示请求/响应/匹配细节）
./veil -u https://example.com -v

# 保存 JSON 报告
./veil -u https://example.com -o results.json

# 保存 HTML 报告
./veil -u https://example.com -o report.html
```

### 网络配置

```bash
# 设置超时
./veil -u https://example.com -timeout 15

# 使用代理
./veil -u https://example.com -proxy http://127.0.0.1:8080

# 跳过 SSL 验证
./veil -u https://example.com -no-verify-ssl

# 不跟随重定向
./veil -u https://example.com -no-follow-redirects
```

### 模板管理

```bash
# 列出所有 POC
./veil -pl

# 查看指定 POC 内容
./veil -pv CVE-2023-5561

# 校验模板（不执行扫描）
./veil -validate -T my_pocs/
```

---

## 模板语法

`.poc` 文件是一种声明式模板格式，用于描述漏洞检测逻辑。

### 基本结构

```
## id: CVE-2023-XXXX
## name: 漏洞名称
## author: 作者
## severity: high
## description: 漏洞描述
## cve: CVE-2023-XXXX
## tags: rce, injection
## reference: https://example.com/advisory

GET /vulnerable/path?param=value
User-Agent: {{random_ua}}

#@ matcher: status_code == 200 && body contains "vulnerable"
```

### 元数据字段

| 字段 | 必填 | 说明 |
|------|------|------|
| `id` | ✓ | 唯一标识符 |
| `name` | ✓ | 漏洞名称 |
| `author` | ✓ | 作者 |
| `severity` | ✓ | critical / high / medium / low / info |
| `cve` | | CVE 编号 |
| `tags` | | 标签，逗号分隔 |
| `description` | | 漏洞描述 |
| `affects` | | 影响的软件/版本 |
| `reference` | | 参考链接（可多行） |
| `cvss-score` | | CVSS 评分 (0.0-10.0) |
| `shodan-query` | | Shodan 搜索语法 |
| `fofa-query` | | FOFA 搜索语法 |

### 变量

```
#$ payload = test_value
#$ paths = /api/v1 | /api/v2 | /api/v3
#$ usernames = @file(users.txt)
```

### 匹配器

```
#@ matcher: status_code == 200
#@ matcher: body contains "success"
#@ matcher: body matches /version[:\s]+(\d+\.\d+)/
#@ matcher: header["Content-Type"] contains "json"
#@ matcher: status_code == 200 && body contains "admin"
#@ matcher: (body contains "root" || body contains "admin") && status_code == 200
#@ condition: and
```

### 提取器

```
#> extract: name=token, regex=/csrf_token[=:]([a-f0-9]+)/, group=1
#> extract: name=version, json=$.data.version
#> extract: name=session, kval=JSESSIONID, from=headers
#> extract: name=internal_val, regex=/id=(\d+)/, internal=true
```

### 多请求链

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

### 攻击模式

```
#$ username = admin | root | test
#$ password = 123456 | admin | password
#@ attack: clusterbomb
```

### OOB 验证

```
GET /api/ssrf?url=http://{{oob_domain}}/probe
#@ oob: dns
#@ matcher: oob_received == true
```

### 内置函数

| 函数 | 示例 | 说明 |
|------|------|------|
| `base64(x)` | `{{base64(payload)}}` | Base64 编码 |
| `url_encode(x)` | `{{url_encode(param)}}` | URL 编码 |
| `md5(x)` | `{{md5(password)}}` | MD5 哈希 |
| `sha256(x)` | `{{sha256(data)}}` | SHA-256 哈希 |
| `to_lower(x)` | `{{to_lower(Name)}}` | 转小写 |
| `random_str(n)` | `{{random_str(8)}}` | 随机字符串 |
| `random_int(a,b)` | `{{random_int(1,100)}}` | 随机整数 |
| `replace(x,a,b)` | `{{replace(str,old,new)}}` | 字符串替换 |

支持嵌套调用: `{{base64({{payload}})}}`

### 内置变量

| 变量 | 说明 |
|------|------|
| `{{Hostname}}` | 目标主机名 |
| `{{Host}}` | 主机名:端口 |
| `{{BaseURL}}` | scheme://host:port |
| `{{Scheme}}` | http 或 https |
| `{{Port}}` | 端口号 |
| `{{Path}}` | URL 路径 |
| `{{random_ua}}` | 随机 User-Agent |
| `{{timestamp}}` | 当前 Unix 时间戳 |
| `{{oob_domain}}` | OOB 回调域名 |
| `{{oob_url}}` | OOB 回调 URL |

---

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-u URL` | 目标 URL（可重复） | |
| `-l FILE` | 目标文件 | |
| `-t PATH` | 模板路径（可重复） | |
| `-T DIR` | 模板目录 | `./veil_poc/` |
| `-id VALUE` | 按 ID 过滤 | |
| `-severity VALUE` | 按严重性过滤 | |
| `-tags VALUE` | 按标签过滤 | |
| `-cve VALUE` | 按 CVE 过滤 | |
| `-timeout N` | 超时秒数 | `10` |
| `-proxy URL` | 代理地址 | |
| `-no-verify-ssl` | 跳过 TLS 验证 | `false` |
| `-no-follow-redirects` | 不跟随重定向 | `false` |
| `-c N` | 并发数 | `10` |
| `-v` | 详细模式 | `false` |
| `-o FILE` | 输出文件 (.json/.html) | |
| `-stats` | 打印统计信息 | `false` |
| `-validate` | 校验模板后退出 | `false` |
| `-pl` | 列出所有 POC | |
| `-pv ID` | 查看指定 POC | |

---

## 许可证

本项目仅供安全研究和授权测试使用。请勿将本工具用于未授权的渗透测试或攻击活动。使用本工具即表示您同意对自己的行为负全部责任。
