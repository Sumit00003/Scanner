"""
libfinder.py
All discovery + analysis for JS recon. Library only -- no CLI.
Public API:
    get_js_files, download_all, detect_all
    ScopeResolver, extract_domains, detect_graphql, detect_websockets
    analyze_comments, run_security_analysis
    CallGraph, build_call_graph, SourceMapParser, parse_source_maps
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ============================================================
# Config
# ============================================================

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/138.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

DEFAULT_TIMEOUT = 20
DEFAULT_WORKERS = 10


def create_session():
    s = requests.Session()
    retry = Retry(
        total=3, backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update(HEADERS)
    return s


# ============================================================
# URL + scope
# ============================================================

SKIP_SCHEMES = {"data", "blob", "javascript", "mailto", "tel", "file", "about"}
CDN_HINTS = (
    "cdn.", "cdnjs.", "unpkg.", "jsdelivr.", "jquery.",
    "bootstrapcdn.", "googleapis.", "gstatic.", "cloudflare.",
    "akamai", "fastly", "amazonaws.com", "azureedge.",
)


def normalize_url(url, base=None):
    if not url:
        return None
    url = url.strip()
    if len(url) >= 2 and url[0] == url[-1] and url[0] in "\"'`":
        url = url[1:-1]
    if base:
        url = urljoin(base, url)
    url, _ = urldefrag(url)
    parsed = urlparse(url)
    if parsed.scheme in SKIP_SCHEMES:
        return None
    if not parsed.scheme:
        url = "https:" + url if url.startswith("//") else "https://" + url
        parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url


def registrable_domain(host):
    if not host:
        return ""
    host = host.lower().split(":")[0]
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_level = {"co", "com", "org", "net", "gov", "ac", "edu"}
    if parts[-2] in two_level and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class ScopeResolver:
    def __init__(self, target_url, allow_subdomains=True, allow_cdn=True):
        self.target = normalize_url(target_url)
        if not self.target:
            raise ValueError(f"Invalid target: {target_url}")
        self.base_domain = registrable_domain(urlparse(self.target).netloc)
        self.allow_subdomains = allow_subdomains
        self.allow_cdn = allow_cdn
        self.stats = defaultdict(int)

    def _is_cdn(self, host):
        return any(h in host.lower() for h in CDN_HINTS)

    def classify(self, url):
        norm = normalize_url(url, base=self.target)
        if not norm:
            self.stats["invalid"] += 1
            return "invalid"
        host = urlparse(norm).netloc.lower().split(":")[0]
        if registrable_domain(host) == self.base_domain:
            self.stats["in_scope"] += 1
            return "in_scope" if host == urlparse(self.target).netloc.lower() else "subdomain"
        if self._is_cdn(host):
            self.stats["cdn"] += 1
            return "cdn"
        self.stats["out_of_scope"] += 1
        return "out_of_scope"

    def in_scope(self, url):  return self.classify(url) in ("in_scope", "subdomain")
    def fetchable(self, url): return self.classify(url) in ("in_scope", "subdomain", "cdn")


# ============================================================
# Crawler
# ============================================================

INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)</script>", re.I)


def extract_scripts(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    js_files = set()
    base_tag = soup.find("base", href=True)
    effective_base = urljoin(base_url, base_tag["href"]) if base_tag else base_url

    for script in soup.find_all("script"):
        src = script.get("src")
        if not src:
            continue
        absolute = normalize_url(src, base=effective_base)
        if absolute:
            js_files.add(absolute)
    return js_files


def extract_inline_scripts(html):
    return [(i, m.group(1)) for i, m in enumerate(INLINE_SCRIPT_RE.finditer(html or ""))]


def fetch_html(session, url):
    r = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    r.raise_for_status()
    return r.text


def get_js_files(url, session=None):
    url = normalize_url(url)
    if not url:
        return set()
    session = session or create_session()
    try:
        html = fetch_html(session, url)
    except Exception as e:
        print(f"[-] Failed to fetch page: {e}", file=sys.stderr)
        return set()
    return extract_scripts(url, html)


# ============================================================
# Downloader
# ============================================================

def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def extract_banner(text):
    m = re.search(r"/\*![\s\S]{0,4096}?\*/", text)
    if m: return m.group(0)
    m = re.search(r"/\*[\s\S]{0,4096}?\*/", text)
    return m.group(0) if m else ""


def extract_source_map(text):
    m = re.search(r"//# sourceMappingURL=(.+)", text)
    return m.group(1).strip() if m else None


def download_one(url, session=None):
    session = session or create_session()
    result = {
        "url": url, "status": None, "content": None, "text": None,
        "sha256": None, "banner": None, "source_map": None,
        "size": 0, "error": None,
    }
    try:
        r = session.get(url, timeout=DEFAULT_TIMEOUT)
        result["status"] = r.status_code
        if r.status_code != 200:
            return result
        content = r.content
        text = r.text
        result.update({
            "content": content,
            "text": text,
            "size": len(content),
            "sha256": sha256(content),
            "banner": extract_banner(text),
            "source_map": extract_source_map(text),
        })
    except Exception as e:
        result["error"] = str(e)
    return result


def download_all(js_urls: Iterable[str], workers=DEFAULT_WORKERS):
    session = create_session()
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(download_one, u, session): u for u in js_urls}
        for f in as_completed(futures):
            results.append(f.result())
    return results


# ============================================================
# Library detector
# ============================================================

VERSION_PATTERNS = [
    r'(?i)\bversion["\']?\s*[:=]\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-._a-zA-Z0-9]*)?)["\']',
    r'(?i)\bVERSION["\']?\s*[:=]\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-._a-zA-Z0-9]*)?)["\']',
    r'v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
]

PACKAGE_PATTERNS = [
    r'"name"\s*:\s*"([^"]+)"',
    r'"version"\s*:\s*"([0-9][^"]*)"',
    r'node_modules/([^/]+)/',
    r'@license\s+([A-Za-z0-9_.\-]+)',
    r'^\s*\*?\s*([A-Za-z0-9_.\- ]+?)\s+v?[0-9]+\.[0-9]+',
]


def filename_analysis(url):
    from pathlib import PurePosixPath
    filename = PurePosixPath(urlparse(url).path).name
    for tag in (".min", ".prod", ".production", ".slim"):
        filename = filename.replace(tag, "")
    m = re.match(r'([A-Za-z0-9_.\-]+?)[-_]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?', filename)
    if not m:
        return None, None
    return m.group(1), m.group(2)


def find_package_name(text):
    for p in PACKAGE_PATTERNS:
        m = re.search(p, text, re.MULTILINE)
        if m:
            return m.group(1)
    return None


def find_version(text):
    for p in VERSION_PATTERNS:
        m = re.search(p, text)
        if m:
            return m.group(1)
    return None


def detect(download):
    url = download["url"]
    text = download.get("text") or ""
    banner = download.get("banner") or ""

    library, version, confidence = None, None, "Low"

    lib, ver = filename_analysis(url)
    if lib:
        library, confidence = lib, "Medium"
    if ver:
        version = ver

    if banner:
        pkg = find_package_name(banner)
        if pkg:
            library, confidence = pkg, "High"
        v = find_version(banner)
        if v:
            version = v

    pkg = find_package_name(text)
    if pkg:
        library, confidence = pkg, "High"
    v = find_version(text)
    if v:
        version = v

    return {
        "url": url,
        "library": library or "Unknown",
        "version": version or "Unknown",
        "confidence": confidence,
        "sha256": download.get("sha256"),
        "source_map": download.get("source_map"),
    }


def detect_all(downloads):
    return [detect(d) for d in downloads if d.get("status") == 200]


# ============================================================
# Domain extractor
# ============================================================

URL_RE = re.compile(r'https?://[^\s"\'`<>()]+', re.I)
PROTO_REL_RE = re.compile(r'(?<![:/])//([A-Za-z0-9.\-]+\.[A-Za-z]{2,})(?::\d+)?', re.I)
HOST_RE = re.compile(r'\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)\b', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

JUNK_TLDS = {"js", "css", "map", "png", "jpg", "jpeg", "gif", "svg",
             "woff", "woff2", "ttf", "eot", "ico", "webp", "mp4", "webm", "wasm"}
SKIP_HOSTS = {"example.com", "example.org", "localhost", "test.com",
              "schema.org", "w3.org", "w3c.org", "mozilla.org"}


def _is_ip(s):
    try:
        ipaddress.ip_address(s); return True
    except ValueError:
        return False


class DomainExtractor:
    def __init__(self, target=None):
        self.target = target
        self.target_domain = registrable_domain(urlparse(target or "").netloc) if target else None
        self.hosts = defaultdict(set)
        self.ip_addresses = defaultdict(set)
        self.internal = set()
        self.third_party = set()

    def scan(self, url, text):
        if not text:
            return
        for m in URL_RE.finditer(text):
            host = urlparse(m.group(0)).netloc.split(":")[0].lower()
            if host:
                self._record(host, url)
        for m in PROTO_REL_RE.finditer(text):
            self._record(m.group(1).lower(), url)
        for m in HOST_RE.finditer(text):
            host = m.group(1).lower()
            if host.split(".")[-1] in JUNK_TLDS:
                continue
            self._record(host, url)
        for m in IP_RE.finditer(text):
            if _is_ip(m.group(0)):
                self.ip_addresses[m.group(0)].add(url)

    def _record(self, host, source):
        if host in SKIP_HOSTS:
            return
        if host.endswith((".local", ".internal")):
            self.internal.add(host)
        self.hosts[host].add(source)
        if self.target_domain and registrable_domain(host) != self.target_domain:
            self.third_party.add(host)

    def report(self):
        domains = {}
        for h, files in self.hosts.items():
            d = registrable_domain(h)
            domains.setdefault(d, {"hosts": set(), "files": set()})
            domains[d]["hosts"].add(h)
            domains[d]["files"].update(files)
        return {
            "domains": [
                {"domain": d, "hosts": sorted(v["hosts"]),
                 "found_in": sorted(v["files"]),
                 "relationship": "first_party" if d == self.target_domain else "third_party"}
                for d, v in sorted(domains.items())
            ],
            "ip_addresses": [{"ip": ip, "found_in": sorted(f)} for ip, f in sorted(self.ip_addresses.items())],
            "internal_hosts": sorted(self.internal),
            "third_party_hosts": sorted(self.third_party),
        }


def extract_domains(downloads, target=None):
    d = DomainExtractor(target=target)
    for it in downloads:
        if it.get("status") == 200:
            d.scan(it["url"], it.get("text") or "")
    return d


# ============================================================
# GraphQL
# ============================================================

GRAPHQL_ENDPOINT_PATTERNS = [
    re.compile(r'["\'`](/[^"\'`\s]*graphql[^"\'`\s]*)["\'`]', re.I),
    re.compile(r'["\'`](https?://[^"\'`\s]*graphql[^"\'`\s]*)["\'`]', re.I),
    re.compile(r'["\'`](/[^"\'`\s]*(?:/gql|/api/graphql|/v\d+/graphql)[^"\'`\s]*)["\'`]', re.I),
    re.compile(r'\bgraphqlUrl\s*[:=]\s*["\'`]([^"\'`]+)["\'`]', re.I),
]
GRAPHQL_QUERY_HINTS = [
    re.compile(r'\b(query|mutation|subscription)\s+([A-Za-z_]\w*)', re.I),
    re.compile(r'__(?:typename|schema)\b'),
    re.compile(r'\bfragment\s+[A-Za-z_]\w*\s+on\s+[A-Za-z_]\w*'),
]
GRAPHQL_INTROSPECTION = re.compile(r'__schema|__type\b|IntrospectionQuery', re.I)
GRAPHQL_MUTATION = re.compile(r'\bmutation\s+([A-Za-z_]\w*)', re.I)
GRAPHQL_QUERY_NAME = re.compile(r'\bquery\s+([A-Za-z_]\w*)', re.I)
GRAPHQL_FRAGMENT = re.compile(r'\bfragment\s+([A-Za-z_]\w*)\s+on\s+([A-Za-z_]\w*)')


class GraphQLDetector:
    def __init__(self, base_url=None):
        self.base_url = base_url
        self.endpoints = defaultdict(set)
        self.operations = {}
        self.fragments = set()
        self.files_with_graphql = set()
        self.introspection_hits = []

    def scan(self, url, text):
        if not text:
            return
        found = False
        for pat in GRAPHQL_ENDPOINT_PATTERNS:
            for m in pat.finditer(text):
                raw = m.group(1)
                resolved = urljoin(self.base_url or url, raw) if self.base_url else raw
                p = urlparse(resolved)
                if p.scheme and p.scheme not in ("http", "https"):
                    continue
                self.endpoints[resolved].add(url)
                found = True
        for pat in GRAPHQL_QUERY_HINTS:
            if pat.search(text):
                found = True
                break
        if GRAPHQL_INTROSPECTION.search(text):
            self.introspection_hits.append(url)
            found = True
        for m in GRAPHQL_MUTATION.finditer(text):
            self.operations[m.group(1)] = {"type": "mutation", "file": url}
            found = True
        for m in GRAPHQL_QUERY_NAME.finditer(text):
            self.operations.setdefault(m.group(1), {"type": "query", "file": url})
            found = True
        for m in GRAPHQL_FRAGMENT.finditer(text):
            self.fragments.add(m.group(1))
            found = True
        if found:
            self.files_with_graphql.add(url)

    def report(self):
        return {
            "endpoints": [{"url": u, "found_in": sorted(f)} for u, f in self.endpoints.items()],
            "operations": [{"name": n, **meta} for n, meta in sorted(self.operations.items())],
            "fragments": sorted(self.fragments),
            "introspection_files": sorted(set(self.introspection_hits)),
            "files_with_graphql": sorted(self.files_with_graphql),
        }


def detect_graphql(downloads, base_url=None):
    g = GraphQLDetector(base_url=base_url)
    for d in downloads:
        if d.get("status") == 200:
            g.scan(d["url"], d.get("text") or "")
    return g


# ============================================================
# WebSocket / SSE
# ============================================================

WS_URL_RE = re.compile(r'["\'`](wss?://[^"\'`\s]+)["\'`]', re.I)
WS_PATH_RE = re.compile(r'["\'`](/[^"\'`\s]*/(?:ws|websocket|socket|socket\.io|sockjs|signalr|hub)[^"\'`\s]*)["\'`]', re.I)
WS_CONSTRUCTOR_RE = re.compile(r'\bnew\s+WebSocket\s*\(', re.I)
WS_SOCKETIO_RE = re.compile(r'\b(?:io|socket\.io|SocketIO)\s*\(', re.I)
WS_SOCKJS_RE = re.compile(r'\bSockJS\s*\(', re.I)
WS_SIGNALR_RE = re.compile(r'\$\.(?:hubConnection|connection)\b|signalR', re.I)
WS_SSE_RE = re.compile(r'\bnew\s+EventSource\s*\(', re.I)
WS_PROTO_RE = re.compile(r'new\s+WebSocket\s*\(\s*[^,]+,\s*["\'`]([^"\'`]+)["\'`]', re.I)


class WebSocketDetector:
    def __init__(self):
        self.urls = defaultdict(set)
        self.paths = defaultdict(set)
        self.constructors = []
        self.protocols = set()

    def scan(self, url, text):
        if not text:
            return
        for m in WS_URL_RE.finditer(text):
            self.urls[m.group(1)].add(url)
        for m in WS_PATH_RE.finditer(text):
            self.paths[m.group(1)].add(url)
        for kind, pat in (
            ("WebSocket", WS_CONSTRUCTOR_RE),
            ("socket.io", WS_SOCKETIO_RE),
            ("SockJS", WS_SOCKJS_RE),
            ("SignalR", WS_SIGNALR_RE),
            ("EventSource", WS_SSE_RE),
        ):
            for m in pat.finditer(text):
                self.constructors.append({
                    "file": url, "kind": kind, "pos": m.start(),
                    "snippet": text[max(0, m.start() - 30): m.start() + 90].replace("\n", " ").strip(),
                })
        for m in WS_PROTO_RE.finditer(text):
            self.protocols.add(m.group(1))

    def report(self):
        return {
            "websocket_urls": [{"url": u, "found_in": sorted(f)} for u, f in self.urls.items()],
            "candidate_paths": [{"path": p, "found_in": sorted(f)} for p, f in self.paths.items()],
            "constructors": self.constructors,
            "protocols": sorted(self.protocols),
        }


def detect_websockets(downloads):
    w = WebSocketDetector()
    for d in downloads:
        if d.get("status") == 200:
            w.scan(d["url"], d.get("text") or "")
    return w


# ============================================================
# Comment analyzer
# ============================================================

BLOCK_COMMENT_RE = re.compile(r"/\*([\s\S]*?)\*/")
LINE_COMMENT_RE = re.compile(r"(?<![:\\])//([^\n]*)")

COMMENT_TAGS = {
    "todo":         re.compile(r"\b(?:TODO|FIXME|XXX|HACK|BUG)\b", re.I),
    "credentials":  re.compile(r"\b(?:password|passwd|pwd|secret|api[_-]?key|token|bearer)\b", re.I),
    "internal_url": re.compile(r"\b(?:https?://)?(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b", re.I),
    "dev_marker":   re.compile(r"\b(?:dev|development|staging|debug|test)\b", re.I),
    "stack_trace":  re.compile(r"\bat\s+[\w$.<>]+\s*\(.*?:\d+:\d+\)", re.I),
    "deprecated":   re.compile(r"\bdeprecated\b", re.I),
    "warning":      re.compile(r"\b(?:WARNING|CAUTION|DANGER)\b", re.I),
    "author":       re.compile(r"@author\b", re.I),
    "source_map":   re.compile(r"sourceMappingURL\s*=\s*(\S+)", re.I),
    "license":      re.compile(r"@license\b", re.I),
}


class CommentAnalyzer:
    def __init__(self, max_len=2000):
        self.max_len = max_len
        self.comments = []
        self.interesting = defaultdict(list)

    def scan(self, url, text):
        if not text:
            return
        for m in BLOCK_COMMENT_RE.finditer(text):
            self._handle(url, m.group(1), "block", m.start())
        for m in LINE_COMMENT_RE.finditer(text):
            self._handle(url, m.group(1), "line", m.start())

    def _handle(self, url, body, kind, start):
        body = body.strip()
        if not body:
            return
        if len(body) > self.max_len:
            body = body[:self.max_len] + "...[truncated]"
        self.comments.append({"file": url, "kind": kind, "start": start, "body": body})
        for tag, pat in COMMENT_TAGS.items():
            if pat.search(body):
                self.interesting[tag].append({
                    "file": url, "kind": kind,
                    "snippet": body[:300].replace("\n", " ").strip(),
                })

    def report(self):
        return {
            "total_comments": len(self.comments),
            "interesting": {t: h for t, h in sorted(self.interesting.items())},
            "sample_comments": self.comments[:25],
        }


def analyze_comments(downloads):
    c = CommentAnalyzer()
    for d in downloads:
        if d.get("status") == 200:
            c.scan(d["url"], d.get("text") or "")
    return c


# ============================================================
# Security: helpers
# ============================================================

def line_col(text, offset):
    line = text.count("\n", 0, offset) + 1
    col = offset - text.rfind("\n", 0, offset)
    return line, col


def _context(text, offset, lines=3):
    parts = text.splitlines()
    ln = text.count("\n", 0, offset)
    start = max(0, ln - lines)
    end = min(len(parts), ln + lines + 1)
    return "\n".join(f"{i+1:5} | {parts[i]}" for i in range(start, end))


def find_function(text, offset):
    before = text[:offset]
    patterns = [
        r"function\s+([A-Za-z0-9_$]+)",
        r"([A-Za-z0-9_$]+)\s*=\s*\([^)]*\)\s*=>",
        r"([A-Za-z0-9_$]+)\s*:\s*function",
        r"class\s+([A-Za-z0-9_$]+)",
    ]
    nearest, pos = None, -1
    for pat in patterns:
        for m in re.finditer(pat, before):
            if m.start() > pos:
                pos, nearest = m.start(), m.group(1)
    return nearest


def _finding(text, url, offset, **kw):
    ln, col = line_col(text, offset)
    base = {
        "file": url, "offset": offset, "line": ln, "column": col,
        "context": _context(text, offset),
        "function": find_function(text, offset),
    }
    base.update(kw)
    return base


# ============================================================
# Security: secrets
# ============================================================

SECRET_PATTERNS = {
    "Google API Key":         [r"AIza[0-9A-Za-z\-_]{35}"],
    "Firebase URL":           [r"https://[A-Za-z0-9\-]+\.firebaseio\.com"],
    "Firebase Storage":       [r"[A-Za-z0-9\-]+\.appspot\.com"],
    "AWS Access Key":         [r"AKIA[0-9A-Z]{16}"],
    "AWS ARN":                [r"arn:aws:[^\s\"']+"],
    "S3 Bucket":              [r"https?://[A-Za-z0-9.\-]+\.s3(?:[.-][A-Za-z0-9-]+)?\.amazonaws\.com"],
    "Azure Storage":          [r"DefaultEndpointsProtocol=https;AccountName=.*?AccountKey=.*?;"],
    "Stripe Publishable Key": [r"pk_(?:live|test)_[A-Za-z0-9]{24,}"],
    "Stripe Secret Key":      [r"sk_(?:live|test)_[A-Za-z0-9]{24,}"],
    "Slack Webhook":          [r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"],
    "Discord Webhook":        [r"https://discord(?:app)?\.com/api/webhooks/[^\s\"']+"],
    "SendGrid API Key":       [r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}"],
    "Mailgun API Key":        [r"key-[0-9a-f]{32}"],
    "Twilio SID":             [r"AC[a-fA-F0-9]{32}"],
    "JWT":                    [r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"],
    "Bearer Token":           [r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"],
    "Basic Auth":             [r"Basic\s+[A-Za-z0-9+/=]{8,}"],
    "Private Key":            [r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----[\s\S]+?-----END (?:RSA|EC|OPENSSH|PRIVATE) KEY-----"],
    "GitHub Token":           [r"gh[pousr]_[A-Za-z0-9]{36,255}"],
    "GitLab Token":           [r"glpat-[A-Za-z0-9\-_]{20,}"],
    "Generic API Key":        [r'(?i)(?:api[_-]?key|apikey|client[_-]?secret|secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})'],
    "OpenAI Key":             [r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"],
    "Anthropic Key":          [r"sk-ant-[A-Za-z0-9\-_]{40,}"],
    "Mapbox Token":           [r"pk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9\-_]{20,}"],
    "Supabase Key":           [r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"],
}

SEVERITY = {
    "HIGH": {
        "AWS Access Key", "Stripe Secret Key", "Private Key",
        "GitHub Token", "GitLab Token", "Azure Storage",
        "SendGrid API Key", "Mailgun API Key", "OpenAI Key", "Anthropic Key",
    },
    "MEDIUM": {"JWT", "Bearer Token", "Basic Auth", "Generic API Key",
               "Twilio SID", "Mapbox Token", "Supabase Key"},
}

NO_VALIDATE = {"Generic API Key", "Bearer Token", "Basic Auth", "AWS ARN",
               "S3 Bucket", "Firebase URL", "Firebase Storage"}


def _severity(name):
    if name in SEVERITY["HIGH"]:
        return "HIGH"
    if name in SEVERITY["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


class SecretValidator:
    def validate(self, secret_type, value):
        method = getattr(
            self,
            "validate_" + secret_type.lower().replace(" ", "_").replace("-", "_"),
            None,
        )
        return method(value) if method else True

    def validate_jwt(self, token):
        parts = token.split(".")
        if len(parts) != 3:
            return False
        try:
            for p in parts[:2]:
                base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))
            return True
        except Exception:
            return False

    def validate_aws_access_key(self, k):
        return bool(re.fullmatch(r"AKIA[0-9A-Z]{16}", k))

    def validate_google_api_key(self, k):
        return bool(re.fullmatch(r"AIza[0-9A-Za-z\-_]{35}", k))

    def validate_stripe_secret_key(self, k):
        return bool(re.fullmatch(r"sk_(live|test)_[A-Za-z0-9]{24,}", k))

    def validate_stripe_publishable_key(self, k):
        return bool(re.fullmatch(r"pk_(live|test)_[A-Za-z0-9]{24,}", k))

    def validate_github_token(self, t):
        return t.startswith(("ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_"))

    def validate_gitlab_token(self, t):
        return t.startswith("glpat-")

    def validate_openai_key(self, k):
        return bool(re.fullmatch(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", k))

    def validate_anthropic_key(self, k):
        return k.startswith("sk-ant-")

    def validate_supabase_key(self, k):
        return self.validate_jwt(k)


class SecretScanner:
    def __init__(self, validate=True):
        self.patterns = SECRET_PATTERNS
        self.validator = SecretValidator() if validate else None
        self.findings = []

    def scan(self, url, text):
        if not text:
            return []
        found = []
        for name, regexes in self.patterns.items():
            for rx in regexes:
                for m in re.finditer(rx, text, re.MULTILINE):
                    raw = m.group(0)
                    validated = None
                    if self.validator and name not in NO_VALIDATE:
                        try:
                            validated = self.validator.validate(name, raw)
                        except Exception:
                            validated = None
                    if validated is False:
                        continue
                    found.append(_finding(
                        text, url, m.start(),
                        type=name, severity=_severity(name),
                        raw=raw,
                        masked=(raw[:6] + "*****" + raw[-4:]) if len(raw) > 12 else raw,
                        validated=validated,
                    ))
        seen, unique = set(), []
        for f in found:
            key = (f["type"], f["offset"], f["file"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        self.findings.extend(unique)
        unique.sort(key=lambda x: (x["severity"] != "HIGH", x["type"]))
        return unique

    def report(self):
        counts = defaultdict(int)
        for f in self.findings:
            counts[f["severity"]] += 1
        return {
            "total": len(self.findings),
            "by_severity": dict(counts),
            "findings": self.findings,
        }


# ============================================================
# Security: entropy
# ============================================================

URL_LIKE = re.compile(r"^https?://|^/|^\.{0,2}/")
HASH_LIKE = re.compile(r"^[a-f0-9]{32,64}$", re.I)


class EntropyDetector:
    def __init__(self, min_length=20, min_entropy=4.3):
        self.min_length = min_length
        self.min_entropy = min_entropy
        self.ignore = {"true", "false", "null", "undefined", "localhost"}
        self.findings = []

    def shannon(self, s):
        if not s:
            return 0.0
        e = 0.0
        for c in set(s):
            p = s.count(c) / len(s)
            e -= p * math.log2(p)
        return e

    def scan(self, url, text):
        if not text:
            return []
        found = []
        pattern = r'["\'`]([A-Za-z0-9+/=_\-]{20,})["\'`]'
        for m in re.finditer(pattern, text):
            value = m.group(1)
            if value.lower() in self.ignore:
                continue
            if URL_LIKE.match(value) or HASH_LIKE.match(value):
                continue
            ent = self.shannon(value)
            if ent < self.min_entropy:
                continue
            found.append(_finding(
                text, url, m.start(1),
                type="High Entropy String", severity="MEDIUM",
                entropy=round(ent, 2),
                confidence=min(100, int(ent * 18)),
                masked=value[:6] + "*****" + value[-4:],
                length=len(value),
            ))
        self.findings.extend(found)
        return found

    def report(self):
        return {"total": len(self.findings), "findings": self.findings}


# ============================================================
# Security: crypto
# ============================================================

CRYPTO_LIBRARIES = {
    "CryptoJS":    [r"\bCryptoJS\b"],
    "WebCrypto":   [r"crypto\.subtle"],
    "Forge":       [r"\bforge\."],
    "SJCL":        [r"\bsjcl\b"],
    "TweetNaCl":   [r"\bnacl\."],
    "Node Crypto": [r"require\(['\"]crypto['\"]\)"],
    "libsodium":   [r"\bsodium\b"],
}
ALGORITHMS = {
    "AES":     [r"AES\.(?:encrypt|decrypt)", r"subtle\.(?:encrypt|decrypt)"],
    "RSA":     [r"\bRSA\b", r"JSEncrypt"],
    "PBKDF2":  [r"\bPBKDF2\b"],
    "HMAC":    [r"HmacSHA", r"\bHMAC\b"],
    "SHA256":  [r"\bSHA256\b", r"SHA-256"],
    "SHA1":    [r"\bSHA1\b", r"SHA-1"],
    "MD5":     [r"\bMD5\b"],
    "ChaCha20":[r"ChaCha20"],
    "Ed25519": [r"Ed25519"],
}
MODES = {
    "CBC": [r"mode\.CBC"], "GCM": [r"\bGCM\b"], "CTR": [r"\bCTR\b"],
    "ECB": [r"mode\.ECB"], "OFB": [r"mode\.OFB"], "CFB": [r"mode\.CFB"],
}
PADDINGS = {
    "Pkcs7": [r"pad\.Pkcs7"], "ZeroPadding": [r"ZeroPadding"],
    "NoPadding": [r"NoPadding"], "ISO10126": [r"pad\.ISO10126"],
    "AnsiX923": [r"pad\.AnsiX923"],
}


class CryptoAnalyzer:
    def __init__(self):
        self.findings = []

    def _detect(self, url, text, patterns, kind):
        out = []
        for name, regexes in patterns.items():
            for rx in regexes:
                for m in re.finditer(rx, text, re.I):
                    out.append(_finding(
                        text, url, m.start(),
                        type=name, kind=kind, severity="INFO",
                        match=m.group(0),
                    ))
        return out

    def analyze(self, url, text):
        if not text:
            return {}
        result = {
            "file": url,
            "libraries":  self._detect(url, text, CRYPTO_LIBRARIES, "library"),
            "algorithms": self._detect(url, text, ALGORITHMS,       "algorithm"),
            "modes":      self._detect(url, text, MODES,            "mode"),
            "padding":    self._detect(url, text, PADDINGS,         "padding"),
        }
        self.findings.append(result)
        return result

    def report(self):
        libs, algos, modes, pads = set(), set(), set(), set()
        for r in self.findings:
            libs.update(x["type"] for x in r["libraries"])
            algos.update(x["type"] for x in r["algorithms"])
            modes.update(x["type"] for x in r["modes"])
            pads.update(x["type"] for x in r["padding"])
        return {
            "files_analyzed": len(self.findings),
            "libraries":  sorted(libs), "algorithms": sorted(algos),
            "modes":      sorted(modes), "padding": sorted(pads),
            "per_file":   self.findings,
        }


# ============================================================
# Security: endpoints
# ============================================================

IGNORE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
              ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
              ".mp3", ".wav", ".map", ".js")

ENDPOINT_PATTERNS = {
    "fetch":        r'fetch\s*\(\s*[\'"`]([^\'"`]+)',
    "axios":        r'axios(?:\.(?:get|post|put|delete|patch|head))?\s*\(\s*[\'"`]([^\'"`]+)',
    "axios_config": r'url\s*:\s*[\'"`]([^\'"`]+)',
    "xhr":          r'\.open\s*\(\s*[\'"][A-Z]+[\'"`]\s*,\s*[\'"`]([^\'"`]+)',
    "jquery":       r'\$\.(?:ajax|get|post)\(\s*[\'"`]([^\'"`]+)',
    "websocket":    r'new\s+WebSocket\s*\(\s*[\'"`]([^\'"`]+)',
    "eventsource":  r'new\s+EventSource\s*\(\s*[\'"`]([^\'"`]+)',
    "graphql":      r'[\'"`]([^\'"`]*?(?:/graphql|/gql)[^\'"`]*?)[\'"`]',
    "relative_api": r'[\'"`](/api/[^\'"`]*|/v\d+/[^\'"`]*|/rest/[^\'"`]*)[\'"`]',
}


class EndpointExtractor:
    def __init__(self):
        self.endpoints = {}

    def _ignore(self, ep):
        el = ep.lower()
        return any(el.endswith(x) for x in IGNORE_EXT)

    def _normalize(self, ep, base):
        if ep.startswith(("http://", "https://", "ws://", "wss://")):
            return ep
        return urljoin(base, ep)

    def extract(self, url, text):
        if not text:
            return []
        raw = defaultdict(set)
        for method, rx in ENDPOINT_PATTERNS.items():
            for m in re.finditer(rx, text, re.I):
                ep = self._normalize(m.group(1), url)
                if self._ignore(ep):
                    continue
                raw[ep].add(method)

        results = []
        for ep, methods in raw.items():
            if "graphql" in methods:   etype = "GraphQL"
            elif "websocket" in methods: etype = "WebSocket"
            elif "eventsource" in methods: etype = "SSE"
            else: etype = "REST"
            confidence = min(100, len(methods) * 25 + 40)

            if ep in self.endpoints:
                self.endpoints[ep]["methods"] = sorted(
                    set(self.endpoints[ep]["methods"]) | set(methods)
                )
                self.endpoints[ep]["found_in"].append(url)
                self.endpoints[ep]["confidence"] = min(
                    100, self.endpoints[ep]["confidence"] + 15
                )
            else:
                self.endpoints[ep] = {
                    "endpoint": ep, "type": etype,
                    "confidence": confidence,
                    "methods": sorted(methods),
                    "found_in": [url],
                }
            results.append(self.endpoints[ep])
        return sorted(results, key=lambda x: -x["confidence"])

    def report(self):
        return {
            "total": len(self.endpoints),
            "endpoints": sorted(
                self.endpoints.values(),
                key=lambda x: -x["confidence"],
            ),
        }


# ============================================================
# Security: one-shot runner
# ============================================================

def run_security_analysis(downloads, validate_secrets=True):
    secrets   = SecretScanner(validate=validate_secrets)
    entropy   = EntropyDetector()
    crypto    = CryptoAnalyzer()
    endpoints = EndpointExtractor()

    for d in downloads:
        if d.get("status") != 200:
            continue
        url, text = d["url"], d.get("text") or ""
        secrets.scan(url, text)
        entropy.scan(url, text)
        crypto.analyze(url, text)
        endpoints.extract(url, text)

    secret_keys = {(s["file"], s["offset"]) for s in secrets.findings}
    entropy.findings = [
        e for e in entropy.findings
        if (e["file"], e["offset"]) not in secret_keys
    ]

    return {"secrets": secrets, "entropy": entropy,
            "crypto": crypto, "endpoints": endpoints}


# ============================================================
# Call graph
# ============================================================

FUNC_DEF_PATTERNS = [
    re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", re.M),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*\(|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)", re.M),
    re.compile(r"\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?function\s*\(", re.M),
]
CALL_PATTERN = re.compile(r"\b([A-Za-z_$][\w$.]*)\s*\(")

INTERESTING_SINKS = {
    "eval", "Function", "setTimeout", "setInterval",
    "fetch", "XMLHttpRequest", "WebSocket", "EventSource",
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
    "postMessage", "document.cookie", "location.href", "location.assign",
    "atob", "btoa", "crypto.subtle", "require", "execScript",
}
IGNORE_CALLS = {
    "if", "for", "while", "switch", "catch", "return", "typeof",
    "new", "delete", "void", "in", "of", "do", "else", "function",
    "class", "super", "this", "yield", "await", "async",
}


def _strip_js(text):
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i) or n
            for k in range(i, j): out[k] = " "
            i = j; continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n": out[k] = " "
            i = j; continue
        if c in ("'", '"', "`"):
            q = c; j = i + 1
            while j < n:
                if text[j] == "\\": j += 2; continue
                if text[j] == q: j += 1; break
                j += 1
            for k in range(i, j):
                if out[k] != "\n": out[k] = " "
            i = j; continue
        i += 1
    return "".join(out)


def _brace_block(text, start):
    if start >= len(text) or text[start] != "{":
        return None
    depth, i, n = 0, start, len(text)
    while i < n:
        if text[i] == "{": depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0: return (start, i)
        i += 1
    return None


class CallGraph:
    def __init__(self):
        self.functions = {}
        self.callers = {}
        self.edges = []
        self.sinks = {}

    def add_file(self, url, text):
        if not text:
            return
        clean = _strip_js(text)
        self._register_functions(url, clean)
        self._register_calls(url, clean)

    def _register_functions(self, url, clean):
        for pat in FUNC_DEF_PATTERNS:
            for m in pat.finditer(clean):
                name = m.group(1)
                brace = clean.find("{", m.end())
                if brace == -1: continue
                block = _brace_block(clean, brace)
                if not block: continue
                start, end = block
                key = f"{name}@{url}"
                if key in self.functions: continue
                self.functions[key] = {
                    "name": name, "file": url,
                    "start": start, "end": end, "calls": set(),
                }

    def _owner_of(self, url, pos):
        best, span = None, None
        for key, fn in self.functions.items():
            if fn["file"] != url: continue
            if fn["start"] <= pos <= fn["end"]:
                s = fn["end"] - fn["start"]
                if span is None or s < span:
                    best, span = key, s
        return best

    def _register_calls(self, url, clean):
        for m in CALL_PATTERN.finditer(clean):
            callee = m.group(1)
            base = callee.split(".")[0]
            if base in IGNORE_CALLS: continue
            caller_key = self._owner_of(url, m.start())
            caller = self.functions[caller_key]["name"] if caller_key else "<top>"
            if caller_key:
                self.functions[caller_key]["calls"].add(callee)
            self.callers.setdefault(callee, set()).add(caller)
            self.edges.append({"caller": caller, "callee": callee,
                               "file": url, "pos": m.start()})
            if callee in INTERESTING_SINKS or base in INTERESTING_SINKS:
                snippet = clean[max(0, m.start() - 40): m.start() + 80].replace("\n", " ")
                self.sinks.setdefault(callee, []).append({
                    "file": url, "caller": caller,
                    "pos": m.start(), "snippet": snippet.strip(),
                })

    def sinks_report(self):
        out = []
        for sink, hits in sorted(self.sinks.items(), key=lambda kv: -len(kv[1])):
            out.append({
                "sink": sink, "hits": len(hits),
                "files": sorted({h["file"] for h in hits}),
                "callers": sorted({h["caller"] for h in hits}),
                "samples": hits[:5],
            })
        return out

    def stats(self):
        return {"functions": len(self.functions), "edges": len(self.edges),
                "unique_callees": len(self.callers), "sinks": len(self.sinks)}


def build_call_graph(downloads):
    cg = CallGraph()
    for d in downloads:
        if d.get("status") == 200 and d.get("text"):
            cg.add_file(d["url"], d["text"])
    return cg


# ============================================================
# Source map parser
# ============================================================

class SourceMapParser:
    def __init__(self, session=None, fetch=True):
        self.session = session or create_session()
        self.fetch = fetch
        self.maps = {}
        self.errors = {}
        self.sources = defaultdict(set)
        self.sources_content = {}

    def parse(self, js_url, source_map_url):
        if not source_map_url:
            return None
        if source_map_url.startswith("data:"):
            try:
                raw = source_map_url.split(",", 1)[1]
                if ";base64" in source_map_url:
                    raw = base64.b64decode(raw).decode("utf-8", "replace")
                data = json.loads(raw)
                self._record(js_url, data)
                return data
            except Exception as e:
                self.errors[js_url] = f"data-url parse error: {e}"
                return None
        if not self.fetch:
            return None
        try:
            r = self.session.get(source_map_url, timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:
                self.errors[js_url] = f"HTTP {r.status_code}"
                return None
            data = r.json()
            self._record(js_url, data)
            return data
        except Exception as e:
            self.errors[js_url] = str(e)
            return None

    def _record(self, js_url, data):
        self.maps[js_url] = data
        for src in data.get("sources", []) or []:
            self.sources[src].add(js_url)
        for src, content in zip(
            data.get("sources", []) or [],
            data.get("sourcesContent", []) or []
        ):
            if content and src not in self.sources_content:
                self.sources_content[src] = content

    def report(self):
        return {
            "maps_parsed": len(self.maps),
            "unique_sources": len(self.sources),
            "sources_with_content": len(self.sources_content),
            "entries": [
                {"js_file": j, "sources_count": len(d.get("sources") or []),
                 "has_content": bool(d.get("sourcesContent")),
                 "source_root": d.get("sourceRoot"), "file": d.get("file"),
                 "first_sources": (d.get("sources") or [])[:10]}
                for j, d in self.maps.items()
            ],
            "errors": self.errors,
        }


def parse_source_maps(downloads, fetch=True, max_maps=50):
    p = SourceMapParser(fetch=fetch)
    count = 0
    for d in downloads:
        if d.get("status") != 200 or not d.get("source_map"):
            continue
        if count >= max_maps:
            break
        url = urljoin(d["url"], d["source_map"])
        p.parse(d["url"], url)
        count += 1
    return p


# ============================================================
# Convenience: run every analyzer in one shot
# ============================================================

def run_recon(url, validate_secrets=True, fetch_source_maps=True):
    """Run the entire discovery + analysis pipeline. Returns a dict."""
    session = create_session()
    js_files = get_js_files(url, session=session)
    if not js_files:
        return {"target": url, "js_files": [], "downloads": [],
                "libraries": [], "secrets": None, "entropy": None,
                "crypto": None, "endpoints": None, "domains": None,
                "graphql": None, "websockets": None, "comments": None,
                "call_graph": None, "source_maps": None}

    downloads = download_all(js_files)
    sec        = run_security_analysis(downloads, validate_secrets=validate_secrets)
    domains    = extract_domains(downloads, target=url)
    graphql    = detect_graphql(downloads, base_url=url)
    websockets = detect_websockets(downloads)
    comments   = analyze_comments(downloads)
    callgraph  = build_call_graph(downloads)
    srcmaps    = parse_source_maps(downloads, fetch=fetch_source_maps)

    return {
        "target": url,
        "js_files": sorted(js_files),
        "downloads": downloads,
        "libraries": detect_all(downloads),
        "secrets": sec["secrets"],
        "entropy": sec["entropy"],
        "crypto": sec["crypto"],
        "endpoints": sec["endpoints"],
        "domains": domains,
        "graphql": graphql,
        "websockets": websockets,
        "comments": comments,
        "call_graph": callgraph,
        "source_maps": srcmaps,
    }
