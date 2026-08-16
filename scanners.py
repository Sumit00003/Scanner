#!/usr/bin/env python3
"""
scanners.py — Combined VAPT Check Library
============================================

Combines four checks into one importable module:

  1. CORS misconfiguration        -> check_cors()
  2. Missing security headers     -> check_security_headers()
  3. Server banner + dangerous
     HTTP method disclosure       -> check_methods() + check_banners()
  4. Clickjacking                 -> check_clickjack_headers() + run_clickjack_poc()

Design notes:
  - None of these functions print to the console. They return dataclasses
    and (where relevant) write evidence files to disk. All console output
    is owned by main.py so the orchestrator controls what's shown and how.
  - Each check can also be run/imported standalone if you want to script
    against just one of them.
  - Only use these against systems you own or are explicitly authorized
    to test.

Requirements:
    pip install requests pillow
    (optional, for clickjacking screenshots) pip install selenium webdriver-manager
"""

import os
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 10


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
                       verify: bool = True, methods: Optional[List[str]] = None) -> Optional[str]:
    """
    Silently replay request(s) for `url` through Burp's proxy so they land
    in Proxy > HTTP History as corroborating evidence. Returns None on
    success, or an error string on failure. methods defaults to ["GET"].
    """
    proxies = {"http": f"http://{burp_proxy}", "https": f"http://{burp_proxy}"}
    methods = methods or ["GET"]
    try:
        for m in methods:
            requests.request(
                m, url, proxies=proxies, timeout=timeout, verify=verify,
                headers={"User-Agent": "vapt-scanner/1.0 (via Burp)"},
            )
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
               timeout: int = DEFAULT_TIMEOUT) -> CorsResult:
    result = CorsResult(url=url)
    session = requests.Session()
    session.headers.update({"User-Agent": "vapt-scanner/1.0"})

    try:
        baseline_resp = session.get(url, timeout=timeout)
    except RequestException as e:
        result.error = f"Baseline request failed: {e}"
        return result

    baseline_headers = dict(baseline_resp.headers)
    if not any(k.lower().startswith(CORS_HEADER_PREFIX) for k in baseline_headers):
        result.has_cors = False
        return result

    result.has_cors = True

    try:
        origin_resp = session.get(url, headers={"Origin": TEST_ORIGIN}, timeout=timeout)
    except RequestException as e:
        result.error = f"Origin-test request failed: {e}"
        return result

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
            null_resp = session.get(url, headers={"Origin": NULL_ORIGIN}, timeout=timeout)
            null_acao = dict(null_resp.headers).get(ACAO)
            result.null_origin_acao = null_acao
            if null_acao is not None and null_acao.strip() == "null":
                result.null_origin_vulnerable = True
                result.add("VULNERABLE: ACAO reflects 'null' origin (trivially spoofable via sandboxed iframe).")
        except RequestException as e:
            result.add(f"Origin: null request failed: {e}")

    if do_preflight:
        try:
            preflight_resp = session.options(
                url,
                headers={
                    "Origin": TEST_ORIGIN,
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "X-Custom-Header",
                },
                timeout=timeout,
            )
            preflight_headers = dict(preflight_resp.headers)
            result.preflight_acam = preflight_headers.get(ACAM)
            result.preflight_acah = preflight_headers.get(ACAH)
        except RequestException as e:
            result.add(f"OPTIONS preflight request failed: {e}")

    return result


# =====================================================================
# 2) Missing security headers
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
IMG_WIDTH = 1000
IMG_PAD = 30


@dataclass
class HeaderCheck:
    url: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status_code: Optional[int] = None
    missing: List[str] = field(default_factory=list)
    present: Dict[str, str] = field(default_factory=dict)
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def vulnerable(self) -> bool:
        return len(self.missing) > 0


def check_security_headers(url: str, timeout: int = DEFAULT_TIMEOUT, verify: bool = True) -> HeaderCheck:
    result = HeaderCheck(url=url)
    try:
        resp = requests.get(url, timeout=timeout, verify=verify, headers={"User-Agent": "vapt-scanner/1.0"})
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
    lines.append((f"Vulnerability: Missing Security Headers - {domain}", font_title, (255, 255, 255)))
    lines.append((f"URL: {check.url}", font_body, TEXT_DIM))
    lines.append((f"Timestamp: {check.timestamp}", font_body, TEXT_DIM))
    lines.append((f"HTTP Status: {check.status_code}", font_body, TEXT_DIM))
    lines.append(("", font_body, TEXT_DIM))

    lines.append((f"Missing Headers ({len(check.missing)})", font_h2, RED))
    for h in check.missing:
        for wl in _wrap_text(f"  - {h}: {SECURITY_HEADERS[h]}", 95):
            lines.append((wl, font_body, RED))
    lines.append(("", font_body, TEXT_DIM))

    if check.present:
        lines.append((f"Present Headers ({len(check.present)})", font_h2, GREEN))
        for h, v in check.present.items():
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
    advertised: List[str] = field(default_factory=list)
    dangerous_advertised: List[str] = field(default_factory=list)
    dav_header: Optional[str] = None
    active_test_results: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class BannerFinding:
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


def check_methods(url: str, timeout: int = DEFAULT_TIMEOUT, active_test: bool = False) -> MethodFinding:
    finding = MethodFinding()
    try:
        resp = requests.options(url, verify=False, timeout=timeout)
    except RequestException as e:
        finding.error = str(e)
        return finding

    allow = resp.headers.get("Allow")
    finding.dav_header = resp.headers.get("DAV")

    if allow:
        finding.advertised = [m.strip().upper() for m in allow.split(",")]
        finding.dangerous_advertised = [m for m in DANGEROUS_METHODS if m in finding.advertised]

    if active_test and finding.dangerous_advertised:
        for method in finding.dangerous_advertised:
            try:
                r = requests.request(method, url, verify=False, timeout=timeout)
                finding.active_test_results[method] = r.status_code
            except RequestException:
                finding.active_test_results[method] = -1

    return finding


def _extract_banners(headers) -> Dict[str, str]:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    return {h: headers_lower[h] for h in BANNER_HEADERS if h in headers_lower}


def check_banners(url: str, timeout: int = DEFAULT_TIMEOUT) -> BannerFinding:
    finding = BannerFinding()
    try:
        normal_resp = requests.get(url, verify=False, timeout=timeout)
        finding.normal_banners = _extract_banners(normal_resp.headers)
    except RequestException as e:
        finding.error = str(e)
        return finding

    try:
        error_resp = requests.get(
            url,
            headers={"X-Invalid-Header": "\x00\x01\x02", "Content-Length": "999999999"},
            params={"test": "'\"<script>"},
            verify=False,
            timeout=timeout,
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
# 4) Clickjacking
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


def check_clickjack_headers(url: str, timeout: int = DEFAULT_TIMEOUT) -> ClickjackCheck:
    result = ClickjackCheck(url=url)
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "vapt-scanner/1.0"})
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
    """Headless-Chrome screenshot of the PoC. Returns None (with no exception)
    if selenium isn't installed or capture fails — caller decides how to report that."""
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
    """Generate the PoC HTML and (optionally) auto-screenshot it. Assumes the
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
