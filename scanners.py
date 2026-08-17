#!/usr/bin/env python3
"""
scanners.py — Combined VAPT Check Library
============================================

Combines checks into one importable module:

  1. CORS misconfiguration              -> check_cors()
  2. Missing / misconfigured security
     headers                            -> check_security_headers()
  3. Server banner + dangerous HTTP
     method disclosure                  -> check_methods() + check_banners()
  4. TRACE method / Cross-Site Tracing  -> check_trace_xst()
  5. Clickjacking                       -> check_clickjack_headers() + run_clickjack_poc()

Cross-cutting features:
  - RateLimiter: pass a shared instance into every check via `rate_limiter=`
    to cap requests/sec across the whole scan.
  - extra_headers: every check accepts `extra_headers` (dict) which gets
    merged into the outbound request — this is how a custom token, cookie,
    or arbitrary header supplied on the CLI reaches every single request,
    including the 401 retry flow.
  - Every result dataclass exposes `status_code` (or per-sub-check status)
    so the orchestrator (main.py) can detect a 401 and decide whether to
    prompt for credentials and retry.

Design notes:
  - These functions do not print to the console or call input() — they
    return dataclasses. All console output and interactive prompting is
    owned by main.py.
  - Only use these against systems you own or are explicitly authorized
    to test.

Requirements:
    pip install requests pillow
    (optional, for clickjacking screenshots) pip install selenium webdriver-manager
"""

import os
import random
import re
import socket
import string
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "vapt-scanner/1.0"


# =====================================================================
# Rate limiter
# =====================================================================
class RateLimiter:
    """Simple minimum-interval rate limiter, safe to share across checks.
    rate_per_sec <= 0 disables limiting entirely."""

    def __init__(self, rate_per_sec: float = 5.0):
        self.min_interval = (1.0 / rate_per_sec) if rate_per_sec and rate_per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last = time.monotonic()


def _merge_headers(base: Optional[Dict[str, str]], extra: Optional[Dict[str, str]]) -> Dict[str, str]:
    merged = dict(base or {})
    if extra:
        merged.update(extra)  # extra (user-supplied auth etc.) wins on conflict
    return merged


def _request(method: str, url: str, timeout: int, rate_limiter: Optional[RateLimiter] = None,
             extra_headers: Optional[Dict[str, str]] = None, verify: bool = True, **kwargs) -> requests.Response:
    if rate_limiter:
        rate_limiter.wait()
    headers = _merge_headers({"User-Agent": DEFAULT_USER_AGENT}, kwargs.pop("headers", None))
    headers = _merge_headers(headers, extra_headers)
    return requests.request(method, url, timeout=timeout, headers=headers, verify=verify, **kwargs)


# =====================================================================
# Shared: Burp helpers
# =====================================================================
def is_burp_running(host: str, port: int) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=2)
        s.close()
        return True
    except OSError:
        return False


def send_through_burp(url: str, burp_proxy: str, timeout: int = DEFAULT_TIMEOUT,
                       verify: bool = True, methods: Optional[List[str]] = None,
                       extra_headers: Optional[Dict[str, str]] = None,
                       rate_limiter: Optional[RateLimiter] = None) -> Optional[str]:
    """Silently replay request(s) for `url` through Burp's proxy so they land
    in Proxy > HTTP History as corroborating evidence."""
    proxies = {"http": f"http://{burp_proxy}", "https": f"http://{burp_proxy}"}
    methods = methods or ["GET"]
    try:
        for m in methods:
            if rate_limiter:
                rate_limiter.wait()
            headers = _merge_headers({"User-Agent": f"{DEFAULT_USER_AGENT} (via Burp)"}, extra_headers)
            requests.request(m, url, proxies=proxies, timeout=timeout, verify=verify, headers=headers)
        return None
    except RequestException as e:
        return str(e)


# =====================================================================
# 1) CORS misconfiguration
# =====================================================================
TEST_ORIGIN = "https://example.test"
NULL_ORIGIN = "null"
ACAO = "Access-Control-Allow-Origin"
ACAC = "Access-Control-Allow-Credentials"
ACAM = "Access-Control-Allow-Methods"
ACAH = "Access-Control-Allow-Headers"
VARY = "Vary"
CORS_HEADER_PREFIX = "access-control-"


@dataclass
class CorsResult:
    url: str
    status_code: Optional[int] = None
    has_cors: bool = False
    acao_test_origin: Optional[str] = None
    reflected: bool = False
    wildcard: bool = False
    acac: Optional[str] = None
    vary: Optional[str] = None
    vary_missing_origin_flag: bool = False
    null_origin_acao: Optional[str] = None
    null_origin_vulnerable: bool = False
    preflight_acam: Optional[str] = None
    preflight_acah: Optional[str] = None
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def add(self, msg: str):
        self.findings.append(msg)

    @property
    def vulnerable(self) -> bool:
        return bool(self.reflected or self.wildcard or self.null_origin_vulnerable
                     or self.vary_missing_origin_flag)


def check_cors(url: str, do_null_origin: bool = True, do_preflight: bool = True,
               timeout: int = DEFAULT_TIMEOUT, extra_headers: Optional[Dict[str, str]] = None,
               rate_limiter: Optional[RateLimiter] = None) -> CorsResult:
    result = CorsResult(url=url)

    try:
        baseline_resp = _request("GET", url, timeout, rate_limiter, extra_headers)
    except RequestException as e:
        result.error = f"Baseline request failed: {e}"
        return result

    result.status_code = baseline_resp.status_code
    baseline_headers = dict(baseline_resp.headers)
    if not any(k.lower().startswith(CORS_HEADER_PREFIX) for k in baseline_headers):
        result.has_cors = False
        return result

    result.has_cors = True

    try:
        origin_resp = _request("GET", url, timeout, rate_limiter, extra_headers,
                                headers={"Origin": TEST_ORIGIN})
    except RequestException as e:
        result.error = f"Origin-test request failed: {e}"
        return result

    result.status_code = origin_resp.status_code
    origin_headers = dict(origin_resp.headers)
    acao_value = origin_headers.get(ACAO)
    result.acao_test_origin = acao_value

    if acao_value is not None:
        if acao_value == TEST_ORIGIN:
            result.reflected = True
            result.add(f"{ACAO} reflects the sent Origin verbatim.")
        if acao_value.strip() == "*":
            result.wildcard = True
            result.add(f"{ACAO} is a wildcard '*'.")

        acac_value = origin_headers.get(ACAC)
        result.acac = acac_value
        if acac_value and acac_value.strip().lower() == "true" and (result.reflected or result.wildcard):
            result.add(f"CRITICAL: {ACAC}: true combined with "
                        f"{'reflected origin' if result.reflected else 'wildcard ACAO'}.")

        vary_value = origin_headers.get(VARY)
        result.vary = vary_value
        if result.reflected and (not vary_value or "origin" not in vary_value.lower()):
            result.vary_missing_origin_flag = True
            result.add("Vary header missing 'Origin' despite dynamic ACAO reflection (cache poisoning risk).")

    if do_null_origin:
        try:
            null_resp = _request("GET", url, timeout, rate_limiter, extra_headers,
                                  headers={"Origin": NULL_ORIGIN})
            null_acao = dict(null_resp.headers).get(ACAO)
            result.null_origin_acao = null_acao
            if null_acao is not None and null_acao.strip() == "null":
                result.null_origin_vulnerable = True
                result.add("VULNERABLE: ACAO reflects 'null' origin (trivially spoofable via sandboxed iframe).")
        except RequestException as e:
            result.add(f"Origin: null request failed: {e}")

    if do_preflight:
        try:
            preflight_resp = _request("OPTIONS", url, timeout, rate_limiter, extra_headers, headers={
                "Origin": TEST_ORIGIN,
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Custom-Header",
            })
            preflight_headers = dict(preflight_resp.headers)
            result.preflight_acam = preflight_headers.get(ACAM)
            result.preflight_acah = preflight_headers.get(ACAH)
        except RequestException as e:
            result.add(f"OPTIONS preflight request failed: {e}")

    return result


# =====================================================================
# 2) Missing / misconfigured security headers
# =====================================================================
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing - HTTPS downgrade / SSL-strip risk.",
    "x-frame-options": "X-Frame-Options missing - possible clickjacking (check CSP frame-ancestors too).",
    "content-security-policy": "Content-Security-Policy missing - no mitigation against XSS/data injection.",
    "x-content-type-options": "X-Content-Type-Options missing - MIME-sniffing risk.",
    "referrer-policy": "Referrer-Policy missing - may leak URLs/tokens via Referer header.",
    "permissions-policy": "Permissions-Policy missing - browser features not restricted.",
}

# ---- evidence image style ----
BG = (25, 27, 31)
HEADER_RED = (176, 0, 32)
TEXT_LIGHT = (230, 230, 230)
TEXT_DIM = (150, 155, 160)
GREEN = (76, 175, 80)
RED = (229, 83, 75)
ORANGE = (255, 152, 0)
IMG_WIDTH = 1000
IMG_PAD = 30


def _validate_header_value(name: str, value: str) -> Optional[str]:
    """Return a misconfiguration note if the present header's VALUE is weak,
    or None if it looks properly configured."""
    v = value.strip()
    vl = v.lower()

    if name == "strict-transport-security":
        m = re.search(r"max-age\s*=\s*(\d+)", vl)
        if not m:
            return "HSTS present but no max-age directive found."
        max_age = int(m.group(1))
        if max_age < 15552000:  # 180 days
            return f"HSTS max-age is only {max_age}s (< 180 days) — recommend >= 15552000."
        if "includesubdomains" not in vl:
            return "HSTS present but missing includeSubDomains (recommended)."
        return None

    if name == "x-frame-options":
        if vl not in ("deny", "sameorigin") and not vl.startswith("allow-from"):
            return f"Non-standard X-Frame-Options value '{v}'."
        return None

    if name == "content-security-policy":
        issues = []
        if "unsafe-inline" in vl:
            issues.append("allows 'unsafe-inline'")
        if "unsafe-eval" in vl:
            issues.append("allows 'unsafe-eval'")
        if re.search(r"default-src\s+\*", vl) or re.search(r"script-src\s+\*", vl):
            issues.append("wildcard (*) source allowed")
        if issues:
            return "CSP present but weak: " + ", ".join(issues) + "."
        return None

    if name == "x-content-type-options":
        if vl != "nosniff":
            return f"X-Content-Type-Options value '{v}' is not 'nosniff'."
        return None

    if name == "referrer-policy":
        weak_values = ("unsafe-url", "no-referrer-when-downgrade")
        if vl in weak_values:
            return f"Referrer-Policy '{v}' leaks more than recommended."
        return None

    if name == "permissions-policy":
        if v.strip() == "":
            return "Permissions-Policy present but empty."
        return None

    return None


@dataclass
class HeaderCheck:
    url: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status_code: Optional[int] = None
    missing: List[str] = field(default_factory=list)
    present: Dict[str, str] = field(default_factory=dict)
    misconfigured: Dict[str, str] = field(default_factory=dict)  # header -> reason
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def vulnerable(self) -> bool:
        return len(self.missing) > 0 or len(self.misconfigured) > 0


def check_security_headers(url: str, timeout: int = DEFAULT_TIMEOUT, verify: bool = True,
                            extra_headers: Optional[Dict[str, str]] = None,
                            rate_limiter: Optional[RateLimiter] = None) -> HeaderCheck:
    result = HeaderCheck(url=url)
    try:
        resp = _request("GET", url, timeout, rate_limiter, extra_headers, verify=verify)
    except RequestException as e:
        result.error = str(e)
        return result

    result.status_code = resp.status_code
    result.request_headers = dict(resp.request.headers)
    result.response_headers = dict(resp.headers)

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for header in SECURITY_HEADERS:
        if header in headers_lower:
            result.present[header] = headers_lower[header]
            issue = _validate_header_value(header, headers_lower[header])
            if issue:
                result.misconfigured[header] = issue
        else:
            result.missing.append(header)

    return result


def _get_font(size: int, bold: bool = False):
    from PIL import ImageFont
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _wrap_text(text: str, max_chars: int) -> List[str]:
    lines = []
    for raw_line in text.split("\n"):
        while len(raw_line) > max_chars:
            lines.append(raw_line[:max_chars])
            raw_line = raw_line[max_chars:]
        lines.append(raw_line)
    return lines


def render_header_evidence_image(check: HeaderCheck, out_path: str) -> str:
    from PIL import Image, ImageDraw

    font_title = _get_font(22, bold=True)
    font_h2 = _get_font(17, bold=True)
    font_body = _get_font(14)
    font_mono = _get_font(13)

    domain = urlparse(check.url).netloc

    lines = []
    lines.append((f"Vulnerability: Security Header Issues - {domain}", font_title, (255, 255, 255)))
    lines.append((f"URL: {check.url}", font_body, TEXT_DIM))
    lines.append((f"Timestamp: {check.timestamp}", font_body, TEXT_DIM))
    lines.append((f"HTTP Status: {check.status_code}", font_body, TEXT_DIM))
    lines.append(("", font_body, TEXT_DIM))

    lines.append((f"Missing Headers ({len(check.missing)})", font_h2, RED))
    for h in check.missing:
        for wl in _wrap_text(f"  - {h}: {SECURITY_HEADERS[h]}", 95):
            lines.append((wl, font_body, RED))
    lines.append(("", font_body, TEXT_DIM))

    if check.misconfigured:
        lines.append((f"Misconfigured Headers ({len(check.misconfigured)})", font_h2, ORANGE))
        for h, reason in check.misconfigured.items():
            for wl in _wrap_text(f"  - {h}: {reason}", 95):
                lines.append((wl, font_body, ORANGE))
        lines.append(("", font_body, TEXT_DIM))

    properly_configured = {h: v for h, v in check.present.items() if h not in check.misconfigured}
    if properly_configured:
        lines.append((f"Properly Configured ({len(properly_configured)})", font_h2, GREEN))
        for h, v in properly_configured.items():
            for wl in _wrap_text(f"  - {h}: {v}", 95):
                lines.append((wl, font_body, GREEN))
        lines.append(("", font_body, TEXT_DIM))

    lines.append(("Response Headers (raw)", font_h2, TEXT_LIGHT))
    for k, v in check.response_headers.items():
        for wl in _wrap_text(f"  {k}: {v}", 100):
            lines.append((wl, font_mono, TEXT_DIM))

    y = IMG_PAD
    line_heights = []
    for text, font, color in lines:
        h = font.getbbox(text or "A")[3] + 8
        line_heights.append(h)
        y += h
    height = y + IMG_PAD

    img = Image.new("RGB", (IMG_WIDTH, height), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, IMG_WIDTH, 6], fill=HEADER_RED)

    y = IMG_PAD
    for (text, font, color), h in zip(lines, line_heights):
        draw.text((IMG_PAD, y), text, font=font, fill=color)
        y += h

    img.save(out_path)
    return out_path


def save_header_raw_evidence(check: HeaderCheck, out_path: str) -> str:
    with open(out_path, "w") as f:
        f.write(f"URL: {check.url}\nTimestamp: {check.timestamp}\nStatus: {check.status_code}\n\n")
        f.write("=== Request Headers ===\n")
        for k, v in check.request_headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n=== Response Headers ===\n")
        for k, v in check.response_headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n=== Missing Security Headers ===\n")
        for h in check.missing:
            f.write(f"{h}: {SECURITY_HEADERS[h]}\n")
        f.write("\n=== Misconfigured Security Headers ===\n")
        for h, reason in check.misconfigured.items():
            f.write(f"{h}: {reason}\n")
    return out_path


# =====================================================================
# 3) Server banner + dangerous HTTP method disclosure
# =====================================================================
DANGEROUS_METHODS = [
    "PUT", "DELETE", "PATCH", "TRACE", "CONNECT",
    "TRACK", "MOVE", "COPY", "PROPFIND", "PROPPATCH",
    "MKCOL", "LOCK", "UNLOCK", "SEARCH",
]

BANNER_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "via", "x-backend-server",
    "x-runtime", "x-turbo-charged-by",
]


@dataclass
class MethodFinding:
    status_code: Optional[int] = None
    advertised: List[str] = field(default_factory=list)
    dangerous_advertised: List[str] = field(default_factory=list)
    dav_header: Optional[str] = None
    active_test_results: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class BannerFinding:
    status_code: Optional[int] = None
    normal_banners: Dict[str, str] = field(default_factory=dict)
    error_status: Optional[int] = None
    error_banners: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class ReconResult:
    url: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    methods: MethodFinding = field(default_factory=MethodFinding)
    banners: BannerFinding = field(default_factory=BannerFinding)

    @property
    def has_dangerous_methods(self) -> bool:
        return len(self.methods.dangerous_advertised) > 0

    @property
    def has_banner_disclosure(self) -> bool:
        return bool(self.banners.normal_banners) or bool(self.banners.error_banners)

    @property
    def vulnerable(self) -> bool:
        return self.has_dangerous_methods or self.has_banner_disclosure


def check_methods(url: str, timeout: int = DEFAULT_TIMEOUT, active_test: bool = False,
                   extra_headers: Optional[Dict[str, str]] = None,
                   rate_limiter: Optional[RateLimiter] = None) -> MethodFinding:
    finding = MethodFinding()
    try:
        resp = _request("OPTIONS", url, timeout, rate_limiter, extra_headers, verify=False)
    except RequestException as e:
        finding.error = str(e)
        return finding

    finding.status_code = resp.status_code
    allow = resp.headers.get("Allow")
    finding.dav_header = resp.headers.get("DAV")

    if allow:
        finding.advertised = [m.strip().upper() for m in allow.split(",")]
        # TRACE is handled by the dedicated check_trace_xst() check instead —
        # exclude it here to avoid a duplicate/confusing finding.
        finding.dangerous_advertised = [m for m in DANGEROUS_METHODS if m in finding.advertised and m != "TRACE"]

    if active_test and finding.dangerous_advertised:
        for method in finding.dangerous_advertised:
            try:
                r = _request(method, url, timeout, rate_limiter, extra_headers, verify=False)
                finding.active_test_results[method] = r.status_code
            except RequestException:
                finding.active_test_results[method] = -1

    return finding


def _extract_banners(headers) -> Dict[str, str]:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    return {h: headers_lower[h] for h in BANNER_HEADERS if h in headers_lower}


def check_banners(url: str, timeout: int = DEFAULT_TIMEOUT,
                   extra_headers: Optional[Dict[str, str]] = None,
                   rate_limiter: Optional[RateLimiter] = None) -> BannerFinding:
    finding = BannerFinding()
    try:
        normal_resp = _request("GET", url, timeout, rate_limiter, extra_headers, verify=False)
        finding.status_code = normal_resp.status_code
        finding.normal_banners = _extract_banners(normal_resp.headers)
    except RequestException as e:
        finding.error = str(e)
        return finding

    try:
        error_resp = _request(
            "GET", url, timeout, rate_limiter, extra_headers, verify=False,
            headers={"X-Invalid-Header": "\x00\x01\x02", "Content-Length": "999999999"},
            params={"test": "'\"<script>"},
        )
        finding.error_status = error_resp.status_code
        if error_resp.status_code >= 500:
            finding.error_banners = _extract_banners(error_resp.headers)
    except RequestException:
        pass

    return finding


def save_recon_evidence(result: ReconResult, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    domain = urlparse(result.url).netloc.replace(":", "_")
    path = os.path.join(out_dir, f"{domain}_recon.txt")

    with open(path, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*70}\nURL: {result.url}\nTimestamp: {result.timestamp}\n\n")
        f.write("--- HTTP Method Disclosure ---\n")
        f.write(f"Advertised methods: {', '.join(result.methods.advertised) or 'none'}\n")
        f.write(f"Dangerous methods advertised: {', '.join(result.methods.dangerous_advertised) or 'none'}\n")
        if result.methods.dav_header:
            f.write(f"DAV header: {result.methods.dav_header}\n")
        if result.methods.active_test_results:
            f.write("Active test results:\n")
            for m, code in result.methods.active_test_results.items():
                f.write(f"  {m}: {code if code != -1 else 'request failed'}\n")

        f.write("\n--- Server Banner Disclosure ---\n")
        if result.banners.normal_banners:
            f.write("Normal response banners:\n")
            for k, v in result.banners.normal_banners.items():
                f.write(f"  {k}: {v}\n")
        else:
            f.write("No banners in normal response.\n")
        if result.banners.error_status is not None:
            f.write(f"Error-trigger status code: {result.banners.error_status}\n")
            for k, v in result.banners.error_banners.items():
                f.write(f"  {k}: {v}\n")

    return path


# =====================================================================
# 4) TRACE method / Cross-Site Tracing (XST) validation
# =====================================================================
@dataclass
class TraceResult:
    url: str
    attempted: bool = False
    status_code: Optional[int] = None
    reflected: bool = False
    evidence_snippet: str = ""
    vulnerable: bool = False
    reason: str = ""
    error: Optional[str] = None


def check_trace_xst(url: str, timeout: int = DEFAULT_TIMEOUT,
                     extra_headers: Optional[Dict[str, str]] = None,
                     rate_limiter: Optional[RateLimiter] = None) -> TraceResult:
    """Actively sends a TRACE request with a unique marker header and checks
    whether the server echoes it back in the response body — that's what
    actually enables Cross-Site Tracing (XST), not just TRACE being listed
    in an Allow header."""
    result = TraceResult(url=url)
    marker = "X-XST-Marker-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
    marker_value = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))

    result.attempted = True
    try:
        resp = _request("TRACE", url, timeout, rate_limiter, extra_headers, verify=False,
                         headers={marker: marker_value})
    except RequestException as e:
        result.error = str(e)
        result.reason = f"TRACE request failed: {e}"
        return result

    result.status_code = resp.status_code

    if resp.status_code in (405, 501, 403, 400):
        result.vulnerable = False
        result.reason = f"TRACE rejected by server (status {resp.status_code})."
        return result

    body = resp.text or ""
    if marker.lower() in body.lower() and marker_value.lower() in body.lower():
        result.reflected = True
        result.vulnerable = True
        result.evidence_snippet = body[:300]
        result.reason = ("Server accepted TRACE and echoed the request headers back in the response body — "
                          "Cross-Site Tracing (XST) is exploitable (can be combined with XSS to read "
                          "HttpOnly cookies/auth headers in older browsers/plugins).")
    else:
        result.vulnerable = False
        result.reason = f"TRACE accepted (status {resp.status_code}) but request was not reflected in the body."

    return result


def save_trace_evidence(result: TraceResult, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    domain = urlparse(result.url).netloc.replace(":", "_")
    path = os.path.join(out_dir, f"{domain}_trace_xst.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"URL: {result.url}\n")
        f.write(f"Status: {result.status_code}\n")
        f.write(f"Reflected: {result.reflected}\n")
        f.write(f"Reason: {result.reason}\n")
        if result.evidence_snippet:
            f.write(f"\n--- Response body (truncated) ---\n{result.evidence_snippet}\n")
    return path


# =====================================================================
# 5) Clickjacking
# =====================================================================
@dataclass
class ClickjackCheck:
    url: str
    status_code: Optional[int] = None
    x_frame_options: Optional[str] = None
    frame_ancestors: Optional[str] = None
    vulnerable: bool = False
    reason: str = ""
    error: Optional[str] = None


def check_clickjack_headers(url: str, timeout: int = DEFAULT_TIMEOUT,
                             extra_headers: Optional[Dict[str, str]] = None,
                             rate_limiter: Optional[RateLimiter] = None) -> ClickjackCheck:
    result = ClickjackCheck(url=url)
    try:
        resp = _request("GET", url, timeout, rate_limiter, extra_headers)
    except RequestException as e:
        result.error = str(e)
        return result

    headers = {k.lower(): v for k, v in resp.headers.items()}
    result.status_code = resp.status_code
    xfo = headers.get("x-frame-options")
    csp = headers.get("content-security-policy")
    result.x_frame_options = xfo

    frame_ancestors = None
    if csp:
        match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
        if match:
            frame_ancestors = match.group(1).strip()
    result.frame_ancestors = frame_ancestors

    if not xfo and not frame_ancestors:
        result.vulnerable = True
        result.reason = "No X-Frame-Options header and no CSP frame-ancestors directive present."
    elif frame_ancestors == "*":
        result.vulnerable = True
        result.reason = "CSP frame-ancestors is '*' (any origin can frame this page)."
    elif xfo and xfo.strip().upper() not in ("DENY", "SAMEORIGIN") and not xfo.strip().upper().startswith("ALLOW-FROM"):
        result.vulnerable = True
        result.reason = f"X-Frame-Options value '{xfo}' is non-standard/unrecognized."
    else:
        result.reason = "Protections present and appear correctly configured."

    return result


def build_clickjack_poc_html(target_url: str) -> str:
    domain = urlparse(target_url).netloc
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Clickjacking PoC - {domain}</title>
<style>
  html, body {{ margin: 0; padding: 0; }}
  .banner {{
    background: #b00020; color: #fff; font-family: Arial, sans-serif;
    font-size: 20px; font-weight: bold; text-align: center; padding: 14px;
  }}
  .container {{ position: relative; width: 100%; height: 90vh; }}
  iframe {{ width: 100%; height: 100%; border: 4px solid #b00020; opacity: 1; }}
</style>
</head>
<body>
  <div class="banner">Application is vulnerable to Clickjacking &mdash; {domain}</div>
  <div class="container">
    <iframe src="{target_url}" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>
  </div>
</body>
</html>
"""


def save_clickjack_poc(target_url: str, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    domain = urlparse(target_url).netloc.replace(":", "_")
    poc_path = os.path.join(out_dir, f"clickjack_poc_{domain}.html")
    with open(poc_path, "w") as f:
        f.write(build_clickjack_poc_html(target_url))
    return poc_path


def take_clickjack_screenshot(poc_path: str, out_dir: str, wait_seconds: int = 3) -> Optional[str]:
    """Headless-Chrome screenshot of the PoC. Returns None (no exception)
    if selenium isn't installed or capture fails."""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            service = Service(ChromeDriverManager().install())
        except ImportError:
            service = Service()
    except ImportError:
        return None

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1400,1000")

    driver = None
    try:
        driver = webdriver.Chrome(service=service, options=options)
        driver.get(f"file://{os.path.abspath(poc_path)}")
        time.sleep(wait_seconds)
        screenshot_path = os.path.join(out_dir, os.path.basename(poc_path).replace(".html", ".png"))
        driver.save_screenshot(screenshot_path)
        return screenshot_path
    except Exception:
        return None
    finally:
        if driver:
            driver.quit()


@dataclass
class ClickjackPocResult:
    poc_path: Optional[str] = None
    screenshot_path: Optional[str] = None
    opened_in_browser: bool = False


def run_clickjack_poc(url: str, out_dir: str, open_browser: bool = False,
                       screenshot: bool = True) -> ClickjackPocResult:
    """Generate the PoC HTML and (optionally) open/screenshot it. Assumes the
    caller already confirmed the target is vulnerable via check_clickjack_headers()."""
    result = ClickjackPocResult()
    result.poc_path = save_clickjack_poc(url, out_dir)

    if open_browser:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(result.poc_path)}")
        result.opened_in_browser = True

    if screenshot:
        result.screenshot_path = take_clickjack_screenshot(result.poc_path, out_dir)

    return result
