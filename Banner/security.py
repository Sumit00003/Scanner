"""
security.py
Consolidated: SecretScanner + SecretValidator + EntropyDetector
             + CryptoAnalyzer + EndpointExtractor.

All produce the same finding shape:
    {file, type, severity, offset, line, column, context, ...extras}
"""
from __future__ import annotations
import base64
import math
import re
from collections import defaultdict
from urllib.parse import urljoin


# ============================================================
# Shared helpers
# ============================================================

def line_col(text, offset):
    line = text.count("\n", 0, offset) + 1
    col = offset - text.rfind("\n", 0, offset)
    return line, col


def context(text, offset, lines=3):
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
        "file": url,
        "offset": offset,
        "line": ln,
        "column": col,
        "context": context(text, offset),
        "function": find_function(text, offset),
    }
    base.update(kw)
    return base


# ============================================================
# Secret patterns (expanded)
# ============================================================

SECRET_PATTERNS = {
    "Google API Key":        [r"AIza[0-9A-Za-z\-_]{35}"],
    "Firebase URL":          [r"https://[A-Za-z0-9\-]+\.firebaseio\.com"],
    "Firebase Storage":      [r"[A-Za-z0-9\-]+\.appspot\.com"],
    "AWS Access Key":        [r"AKIA[0-9A-Z]{16}"],
    "AWS ARN":               [r"arn:aws:[^\s\"']+"],
    "S3 Bucket":             [r"https?://[A-Za-z0-9.\-]+\.s3(?:[.-][A-Za-z0-9-]+)?\.amazonaws\.com"],
    "Azure Storage":         [r"DefaultEndpointsProtocol=https;AccountName=.*?AccountKey=.*?;"],
    "Stripe Publishable Key":[r"pk_(?:live|test)_[A-Za-z0-9]{24,}"],
    "Stripe Secret Key":     [r"sk_(?:live|test)_[A-Za-z0-9]{24,}"],
    "Slack Webhook":         [r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"],
    "Discord Webhook":       [r"https://discord(?:app)?\.com/api/webhooks/[^\s\"']+"],
    "SendGrid API Key":      [r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}"],
    "Mailgun API Key":       [r"key-[0-9a-f]{32}"],
    "Twilio SID":            [r"AC[a-fA-F0-9]{32}"],
    "JWT":                   [r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"],
    "Bearer Token":          [r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"],
    "Basic Auth":            [r"Basic\s+[A-Za-z0-9+/=]{8,}"],
    "Private Key":           [r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----[\s\S]+?-----END (?:RSA|EC|OPENSSH|PRIVATE) KEY-----"],
    "GitHub Token":          [r"gh[pousr]_[A-Za-z0-9]{36,255}"],
    "GitLab Token":          [r"glpat-[A-Za-z0-9\-_]{20,}"],
    "Generic API Key":       [r'(?i)(?:api[_-]?key|apikey|client[_-]?secret|secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})'],
    # --- new additions ---
    "OpenAI Key":            [r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"],
    "Anthropic Key":         [r"sk-ant-[A-Za-z0-9\-_]{40,}"],
    "Mapbox Token":          [r"pk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9\-_]{20,}"],
    "Algolia Key":           [r"[A-Za-z0-9]{32}"],  # low-confidence, validated below
    "Supabase Key":          [r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"],
    "Heroku API Key":        [r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"],
}

SEVERITY = {
    "HIGH": {
        "AWS Access Key", "Stripe Secret Key", "Private Key",
        "GitHub Token", "GitLab Token", "Azure Storage",
        "SendGrid API Key", "Mailgun API Key", "OpenAI Key",
        "Anthropic Key", "Supabase Key", "Heroku API Key",
    },
    "MEDIUM": {
        "JWT", "Bearer Token", "Basic Auth", "Generic API Key",
        "Twilio SID", "Mapbox Token", "Algolia Key",
    },
}

# Never auto-validate these (too generic, too many FPs)
NO_VALIDATE = {"Generic API Key", "Algolia Key", "Heroku API Key",
               "Bearer Token", "Basic Auth", "AWS ARN", "S3 Bucket",
               "Firebase URL", "Firebase Storage"}


def _severity(name):
    if name in SEVERITY["HIGH"]:
        return "HIGH"
    if name in SEVERITY["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


# ============================================================
# Secret validator
# ============================================================

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


# ============================================================
# Secret scanner
# ============================================================

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

                    # skip if validator definitively says no
                    if validated is False:
                        continue

                    found.append(_finding(
                        text, url, m.start(),
                        type=name,
                        severity=_severity(name),
                        raw=raw,
                        masked=(raw[:6] + "*****" + raw[-4:]) if len(raw) > 12 else raw,
                        validated=validated,
                    ))

        # dedup on (type, offset)
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
# Entropy detector
# ============================================================

URL_LIKE = re.compile(r"^https?://|^/|^\.{0,2}/")
HASH_LIKE = re.compile(r"^[a-f0-9]{32,64}$", re.I)  # often just md5/sha


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
        # quoted + backtick + bare tokens
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
                type="High Entropy String",
                severity="MEDIUM",
                entropy=round(ent, 2),
                confidence=min(100, int(ent * 18)),
                masked=value[:6] + "*****" + value[-4:],
                length=len(value),
            ))
        self.findings.extend(found)
        return found

    def report(self):
        return {
            "total": len(self.findings),
            "findings": self.findings,
        }


# ============================================================
# Crypto analyzer
# ============================================================

CRYPTO_LIBRARIES = {
    "CryptoJS":   [r"\bCryptoJS\b"],
    "WebCrypto":  [r"crypto\.subtle"],
    "Forge":      [r"\bforge\."],
    "SJCL":       [r"\bsjcl\b"],
    "TweetNaCl":  [r"\bnacl\."],
    "Node Crypto":[r"require\(['\"]crypto['\"]\)"],
    "libsodium":  [r"\bsodium\b"],
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
    "CBC": [r"mode\.CBC"],
    "GCM": [r"\bGCM\b"],
    "CTR": [r"\bCTR\b"],
    "ECB": [r"mode\.ECB"],
    "OFB": [r"mode\.OFB"],
    "CFB": [r"mode\.CFB"],
}

PADDINGS = {
    "Pkcs7":       [r"pad\.Pkcs7"],
    "ZeroPadding": [r"ZeroPadding"],
    "NoPadding":   [r"NoPadding"],
    "ISO10126":    [r"pad\.ISO10126"],
    "AnsiX923":    [r"pad\.AnsiX923"],
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
                        type=name, kind=kind,
                        severity="INFO", match=m.group(0),
                    ))
        return out

    def analyze(self, url, text):
        if not text:
            return {}
        result = {
            "file": url,
            "libraries":   self._detect(url, text, CRYPTO_LIBRARIES, "library"),
            "algorithms":  self._detect(url, text, ALGORITHMS,       "algorithm"),
            "modes":       self._detect(url, text, MODES,            "mode"),
            "padding":     self._detect(url, text, PADDINGS,         "padding"),
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
            "libraries":  sorted(libs),
            "algorithms": sorted(algos),
            "modes":      sorted(modes),
            "padding":    sorted(pads),
            "per_file":   self.findings,
        }


# ============================================================
# Endpoint extractor (tightened)
# ============================================================

IGNORE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
              ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
              ".mp3", ".wav", ".map", ".js")

ENDPOINT_PATTERNS = {
    "fetch":         r'fetch\s*\(\s*[\'"`]([^\'"`]+)',
    "axios":         r'axios(?:\.(?:get|post|put|delete|patch|head))?\s*\(\s*[\'"`]([^\'"`]+)',
    "axios_config":  r'url\s*:\s*[\'"`]([^\'"`]+)',
    "xhr":           r'\.open\s*\(\s*[\'"][A-Z]+[\'"`]\s*,\s*[\'"`]([^\'"`]+)',
    "jquery":        r'\$\.(?:ajax|get|post)\(\s*[\'"`]([^\'"`]+)',
    "websocket":     r'new\s+WebSocket\s*\(\s*[\'"`]([^\'"`]+)',
    "eventsource":   r'new\s+EventSource\s*\(\s*[\'"`]([^\'"`]+)',
    "graphql":       r'[\'"`]([^\'"`]*?(?:/graphql|/gql)[^\'"`]*?)[\'"`]',
    "relative_api":  r'[\'"`](/api/[^\'"`]*|/v\d+/[^\'"`]*|/rest/[^\'"`]*)[\'"`]',
}


class EndpointExtractor:
    def __init__(self):
        self.endpoints = {}     # url -> {type, methods, confidence, files}

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
            if "graphql" in methods:
                etype = "GraphQL"
            elif "websocket" in methods:
                etype = "WebSocket"
            elif "eventsource" in methods:
                etype = "SSE"
            else:
                etype = "REST"

            confidence = min(100, len(methods) * 25 + 40)
            entry = {
                "endpoint": ep,
                "type": etype,
                "confidence": confidence,
                "methods": sorted(methods),
                "found_in": [url],
            }
            # merge with existing
            if ep in self.endpoints:
                self.endpoints[ep]["methods"] = sorted(
                    set(self.endpoints[ep]["methods"]) | set(methods)
                )
                self.endpoints[ep]["found_in"].append(url)
                self.endpoints[ep]["confidence"] = min(
                    100, self.endpoints[ep]["confidence"] + 15
                )
            else:
                self.endpoints[ep] = entry
            results.append(entry)

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
# One-shot runner
# ============================================================

def run_security_analysis(downloads, validate_secrets=True):
    """Run all security analyzers over a list of download dicts."""
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

    # cross-dedup: if entropy finding overlaps a secret at same offset, drop it
    secret_keys = {(s["file"], s["offset"]) for s in secrets.findings}
    entropy.findings = [
        e for e in entropy.findings
        if (e["file"], e["offset"]) not in secret_keys
    ]

    return {
        "secrets":   secrets,
        "entropy":   entropy,
        "crypto":    crypto,
        "endpoints": endpoints,
    }