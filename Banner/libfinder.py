"""
libfinder.py
Consolidated core: crawler + downloader + detector + scope + domain +
graphql + websocket + comments + correlator + CLI.

Security analyzers (secrets, entropy, crypto, endpoints) live in
security.py and are wired into the CLI + Correlator here.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from security import run_security_analysis


# ============================================================
# Shared config
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
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(HEADERS)
    return session


# ============================================================
# Scope resolution
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
    """Return list of (index, source) for inline <script> blocks."""
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
# Detector (filename / banner / body)
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
        ipaddress.ip_address(s)
        return True
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
# GraphQL detector
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
# WebSocket detector
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
# Correlator (now indexes security findings too)
# ============================================================

def _host(url):
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


class Correlator:
    def __init__(self, downloads, findings, secrets=None, endpoints=None,
                 domains=None, comments=None, graphql=None, websockets=None,
                 entropy=None, crypto=None):
        self.downloads = downloads
        self.findings = findings or []
        self.secrets = secrets
        self.endpoints = endpoints
        self.domains = domains
        self.comments = comments
        self.graphql = graphql
        self.websockets = websockets
        self.entropy = entropy
        self.crypto = crypto

        self.by_hash = defaultdict(list)
        self.by_host = defaultdict(set)
        self.per_file = defaultdict(dict)

    # --------------------------------------------------------
    def run(self):
        self._index_downloads()
        self._index_findings()
        self._index_secrets()
        self._index_entropy()
        self._index_endpoints()
        self._index_domains()
        self._index_comments()
        self._index_crypto()
        return self.report()

    # --------------------------------------------------------
    def _index_downloads(self):
        for d in self.downloads:
            if d.get("status") != 200:
                continue
            url = d["url"]
            self.by_hash[d["sha256"]].append(url)
            self.by_host[_host(url)].add(url)
            self.per_file[url].update({
                "size": d.get("size"),
                "sha256": d.get("sha256"),
                "has_source_map": bool(d.get("source_map")),
                "has_banner": bool(d.get("banner")),
            })

    def _index_findings(self):
        for f in self.findings:
            url = f.get("url")
            if not url:
                continue
            # findings may be grouped (library/version list) OR per-file
            if isinstance(url, list):
                for u in url:
                    self.per_file[u].setdefault("libraries", []).append({
                        "name": f.get("library"),
                        "version": f.get("version"),
                        "confidence": f.get("confidence"),
                    })
            else:
                self.per_file[url].setdefault("libraries", []).append({
                    "name": f.get("library"),
                    "version": f.get("version"),
                    "confidence": f.get("confidence"),
                })

    # --------------------------------------------------------
    # NEW: secrets now come from security.SecretScanner
    # --------------------------------------------------------
    def _index_secrets(self):
        if not self.secrets:
            return
        items = getattr(self.secrets, "findings", None) or self.secrets
        for s in items:
            url = s.get("file") or s.get("url")
            if not url:
                continue
            self.per_file[url].setdefault("secrets", []).append({
                "type": s.get("type"),
                "severity": s.get("severity"),
                "validated": s.get("validated"),
                "masked": s.get("masked") or (s.get("raw") or "")[:12],
                "line": s.get("line"),
            })

    # --------------------------------------------------------
    # NEW: entropy hits
    # --------------------------------------------------------
    def _index_entropy(self):
        if not self.entropy:
            return
        items = getattr(self.entropy, "findings", None) or self.entropy
        for e in items:
            url = e.get("file") or e.get("url")
            if not url:
                continue
            self.per_file[url].setdefault("entropy", []).append({
                "entropy": e.get("entropy"),
                "masked": e.get("masked"),
                "line": e.get("line"),
            })

    # --------------------------------------------------------
    # NEW: crypto usage
    # --------------------------------------------------------
    def _index_crypto(self):
        if not self.crypto:
            return
        per_file = getattr(self.crypto, "findings", None) or []
        for entry in per_file:
            url = entry.get("file")
            if not url:
                continue
            libs  = [x["type"] for x in entry.get("libraries", [])]
            algos = [x["type"] for x in entry.get("algorithms", [])]
            if libs or algos:
                self.per_file[url].setdefault("crypto", {
                    "libraries":  sorted(set(libs)),
                    "algorithms": sorted(set(algos)),
                })

    # --------------------------------------------------------
    # endpoints: works with EndpointExtractor.report()
    # --------------------------------------------------------
    def _index_endpoints(self):
        if not self.endpoints:
            return
        # Accept either an EndpointExtractor instance or a raw dict/list
        if hasattr(self.endpoints, "report"):
            items = self.endpoints.report().get("endpoints", [])
        else:
            items = self.endpoints
            if isinstance(items, dict):
                items = items.get("endpoints", [])

        for e in items or []:
            target = e.get("endpoint") or e.get("url")
            srcs = e.get("found_in") or e.get("file") or []
            if isinstance(srcs, str):
                srcs = [srcs]
            for u in srcs:
                self.per_file[u].setdefault("endpoints", []).append({
                    "endpoint": target,
                    "type": e.get("type"),
                    "confidence": e.get("confidence"),
                })

    def _index_domains(self):
        if not self.domains:
            return
        rep = self.domains.report() if hasattr(self.domains, "report") else self.domains
        for d in rep.get("domains", []):
            for file in d.get("found_in", []):
                self.per_file[file].setdefault("domains", []).append(d["domain"])

    def _index_comments(self):
        if not self.comments:
            return
        rep = self.comments.report() if hasattr(self.comments, "report") else self.comments
        for tag, hits in rep.get("interesting", {}).items():
            for h in hits:
                self.per_file[h["file"]].setdefault("comment_flags", []).append(tag)

    # --------------------------------------------------------
    def report(self):
        duplicates = {h: urls for h, urls in self.by_hash.items() if len(urls) > 1}

        host_libs = defaultdict(set)
        for url, info in self.per_file.items():
            for lib in info.get("libraries", []):
                host_libs[_host(url)].add(f"{lib['name']}@{lib['version']}")

        families = defaultdict(list)
        for url in self.per_file:
            h = _host(url)
            path = urlparse(url).path
            base = (path.rsplit("/", 1)[-1] or path).split(".")[0]
            families[(h, base)].append(url)

        risky = []
        for url, info in self.per_file.items():
            secrets = info.get("secrets", [])
            # weight by severity + validated
            score = 0
            for s in secrets:
                sev = (s.get("severity") or "").upper()
                w = {"HIGH": 10, "MEDIUM": 5, "LOW": 2}.get(sev, 1)
                if s.get("validated") is True:
                    w *= 2
                score += w
            score += len(info.get("comment_flags", []))
            score += 2 if info.get("has_source_map") else 0
            score += len(info.get("entropy", []))
            score += 1 if info.get("crypto", {}).get("libraries") else 0

            if score:
                risky.append({
                    "url": url, "score": score,
                    "flags": {
                        "secrets": len(secrets),
                        "entropy": len(info.get("entropy", [])),
                        "comments": info.get("comment_flags", []),
                        "crypto": info.get("crypto", {}),
                        "has_source_map": info.get("has_source_map", False),
                    },
                })
        risky.sort(key=lambda r: -r["score"])

        return {
            "hosts": sorted(self.by_host.keys()),
            "files": len(self.per_file),
            "duplicates": [{"sha256": h, "urls": u} for h, u in duplicates.items()],
            "host_libraries": {h: sorted(l) for h, l in host_libs.items()},
            "bundle_families": [
                {"host": h, "base": b, "urls": u}
                for (h, b), u in families.items() if len(u) > 1
            ],
            "risky_files": risky,
            "per_file": dict(self.per_file),
        }


def correlate(downloads, findings, **extra):
    return Correlator(downloads, findings, **extra).run()


# ============================================================
# CLI
# ============================================================

def cmd_scan(args):
    print("=" * 60)
    print(" LibFinder - JavaScript Recon Toolkit")
    print("=" * 60)

    session = create_session()
    scope = ScopeResolver(args.url)

    js_files = get_js_files(args.url, session=session)
    print(f"\n[+] Target   : {args.url}")
    print(f"[+] JS files : {len(js_files)}")

    if not js_files:
        return

    downloads = download_all(js_files)
    findings = detect_all(downloads)

    # ---------- SECURITY PASS (NEW) ----------
    print("[+] Running security pass...")
    sec = run_security_analysis(
        downloads,
        validate_secrets=not args.no_validate_secrets,
    )
    secrets   = sec["secrets"]
    entropy   = sec["entropy"]
    crypto    = sec["crypto"]
    endpoints = sec["endpoints"]

    # ---------- Structural analyzers ----------
    domains    = extract_domains(downloads, target=args.url)
    graphql    = detect_graphql(downloads, base_url=args.url)
    websockets = detect_websockets(downloads)
    comments   = analyze_comments(downloads)

    # ---------- Correlate ----------
    correlation = correlate(
        downloads, findings,
        secrets=secrets,
        endpoints=endpoints,
        domains=domains,
        comments=comments,
        graphql=graphql,
        websockets=websockets,
        entropy=entropy,
        crypto=crypto,
    )

    # ============================================================
    # OUTPUT
    # ============================================================

    # -------- Libraries --------
    print("\n" + "=" * 60)
    print(" Libraries")
    print("=" * 60)
    for f in findings:
        print(f"  {f['library']:<30} {f['version']:<15} "
              f"[{f['confidence']}] {f['url']}")

    # -------- Secrets --------
    srep = secrets.report()
    print("\n" + "=" * 60)
    print(f" Secrets ({srep['total']})  {srep['by_severity']}")
    print("=" * 60)
    if not secrets.findings:
        print("  (none)")
    for s in secrets.findings[:30]:
        if s.get("validated") is True:
            mark = "✓"
        elif s.get("validated") is False:
            mark = "✗"
        else:
            mark = " "
        print(f"  [{mark}] [{s['severity']:<6}] {s['type']:<22} "
              f"{s['masked']}  @ {s['file'].split('/')[-1]}:{s['line']}")

    # -------- Entropy --------
    erep = entropy.report()
    if erep["total"]:
        print("\n" + "=" * 60)
        print(f" High-Entropy Strings ({erep['total']})")
        print("=" * 60)
        for e in entropy.findings[:20]:
            print(f"  H={e['entropy']:<5} {e['masked']}  "
                  f"@ {e['file'].split('/')[-1]}:{e['line']}")

    # -------- Crypto --------
    crep = crypto.report()
    if crep["libraries"] or crep["algorithms"]:
        print("\n" + "=" * 60)
        print(" Crypto Usage")
        print("=" * 60)
        print(f"  libraries : {', '.join(crep['libraries']) or '-'}")
        print(f"  algorithms: {', '.join(crep['algorithms']) or '-'}")
        print(f"  modes     : {', '.join(crep['modes']) or '-'}")
        print(f"  padding   : {', '.join(crep['padding']) or '-'}")

    # -------- Endpoints --------
    xrep = endpoints.report()
    if xrep["total"]:
        print("\n" + "=" * 60)
        print(f" Endpoints ({xrep['total']})")
        print("=" * 60)
        for e in xrep["endpoints"][:25]:
            print(f"  [{e['type']:<9}] {e['confidence']:>3}  {e['endpoint']}")

    # -------- Domains --------
    drep = domains.report()
    if drep["domains"]:
        print("\n" + "=" * 60)
        print(f" Domains ({len(drep['domains'])})")
        print("=" * 60)
        for d in drep["domains"]:
            print(f"  [{d['relationship']:<11}] {d['domain']}  "
                  f"({len(d['hosts'])} hosts, {len(d['found_in'])} files)")

    # -------- GraphQL --------
    gql = graphql.report()
    if gql["endpoints"] or gql["operations"]:
        print("\n" + "=" * 60)
        print(" GraphQL")
        print("=" * 60)
        for e in gql["endpoints"]:
            print(f"  endpoint: {e['url']}")
        for op in gql["operations"]:
            print(f"  {op['type']:<10} {op['name']}")
        if gql["introspection_files"]:
            print(f"  [!] Introspection strings in "
                  f"{len(gql['introspection_files'])} file(s)")

    # -------- WebSockets --------
    ws = websockets.report()
    if ws["websocket_urls"] or ws["constructors"]:
        print("\n" + "=" * 60)
        print(" WebSockets / SSE")
        print("=" * 60)
        for u in ws["websocket_urls"]:
            print(f"  url: {u['url']}")
        for c in ws["constructors"][:10]:
            print(f"  {c['kind']:<12} in {c['file'].split('/')[-1]}")
        if ws["protocols"]:
            print(f"  protocols: {', '.join(ws['protocols'])}")

    # -------- Comments --------
    rep = comments.report()
    print("\n" + "=" * 60)
    print(f" Comments ({rep['total_comments']} total)")
    print("=" * 60)
    for tag, hits in rep["interesting"].items():
        print(f"  {tag:<14} x{len(hits)}")

    # -------- Risky Files --------
    print("\n" + "=" * 60)
    print(" Risky Files")
    print("=" * 60)
    for r in correlation["risky_files"][:20]:
        print(f"  score={r['score']:<3} {r['url']}")

    # -------- JSON export --------
    if args.json:
        out = {
            "target": args.url,
            "findings": findings,
            "secrets": srep,
            "entropy": erep,
            "crypto": crep,
            "endpoints": xrep,
            "domains": drep,
            "graphql": gql,
            "websockets": ws,
            "comments": rep,
            "correlation": correlation,
        }
        Path(args.json).write_text(
            json.dumps(out, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"\n[+] JSON report written to {args.json}")


def main():
    p = argparse.ArgumentParser(description="LibFinder - JS recon toolkit")
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument("--json", help="Write a JSON report to this path")
    p.add_argument("--no-validate-secrets", action="store_true",
                   help="Skip secret validation (faster, more FPs)")
    args = p.parse_args()
    cmd_scan(args)


if __name__ == "__main__":
    main()
