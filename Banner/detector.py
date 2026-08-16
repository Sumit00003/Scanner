import re
from urllib.parse import urlparse
from pathlib import PurePosixPath


# Generic version patterns
VERSION_PATTERNS = [
    r'(?i)\bversion["\']?\s*[:=]\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-._a-zA-Z0-9]*)?)["\']',
    r'(?i)\bVERSION["\']?\s*[:=]\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-._a-zA-Z0-9]*)?)["\']',
    r'v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
]


# Package name hints
PACKAGE_PATTERNS = [

    # package.json
    r'"name"\s*:\s*"([^"]+)"',
    r'"version"\s*:\s*"([0-9][^"]*)"',


    # webpack paths
    r'node_modules/([^/]+)/',

    # npm package metadata
    r'@license\s+([A-Za-z0-9_.\-]+)',

    # banner comments
    r'^\s*\*?\s*([A-Za-z0-9_.\- ]+?)\s+v?[0-9]+\.[0-9]+',

]


def filename_analysis(url):
    """
    Detect:
    jquery-3.7.1.min.js
    react.production.min.js
    vue.runtime.global.js
    """

    filename = PurePosixPath(urlparse(url).path).name

    filename = filename.replace(".min", "")
    filename = filename.replace(".prod", "")
    filename = filename.replace(".production", "")
    filename = filename.replace(".slim", "")

    match = re.match(
        r'([A-Za-z0-9_.\-]+?)[-_]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
        filename
    )

    if not match:
        return None, None

    return match.group(1), match.group(2)


def find_package_name(text):

    for pattern in PACKAGE_PATTERNS:

        m = re.search(pattern, text, re.MULTILINE)

        if m:
            return m.group(1)

    return None


def find_version(text):

    for pattern in VERSION_PATTERNS:

        m = re.search(pattern, text)

        if m:
            return m.group(1)

    return None


def detect(download):

    url = download["url"]

    text = download["text"] or ""

    banner = download.get("banner") or ""

    library = None
    version = None
    confidence = "Low"

    # -------------------------
    # filename
    # -------------------------
    lib, ver = filename_analysis(url)

    if lib:
        library = lib
        confidence = "Medium"

    if ver:
        version = ver

    # -------------------------
    # banner
    # -------------------------
    if banner:

        pkg = find_package_name(banner)

        if pkg:
            library = pkg
            confidence = "High"

        ver = find_version(banner)

        if ver:
            version = ver

    # -------------------------
    # full JS
    # -------------------------
    pkg = find_package_name(text)

    if pkg:
        library = pkg
        confidence = "High"

    ver = find_version(text)

    if ver:
        version = ver

    return {
        "url": url,
        "library": library or "Unknown",
        "version": version or "Unknown",
        "confidence": confidence,
        "sha256": download["sha256"],
        "source_map": download["source_map"],
    }


def detect_all(downloads):

    findings = []

    for item in downloads:

        if item["status"] != 200:
            continue

        findings.append(detect(item))

    return findings