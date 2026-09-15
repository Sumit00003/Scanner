"""
source_map_parser.py
Resolve //# sourceMappingURL, download .map files, recover original
filenames, and pull out interesting original source snippets.

This is intentionally light: it doesn't try to reconstruct the full
original source, only the file list + size summary + a peek at the
first N chars of any embedded sourcesContent.
"""
import json
import os
from urllib.parse import urljoin, urlparse

import requests
from libfinder import create_session

#from downloader import create_session


def resolve_sourcemap_url(js_url, source_map):
    """source_map is the raw value from the JS comment (may be relative)."""
    if not source_map:
        return None
    if source_map.startswith("data:"):
        return source_map
    return urljoin(js_url, source_map)


class SourceMapParser:
    def __init__(self, session=None, fetch=True):
        self.session = session or create_session()
        self.fetch = fetch
        self.maps = {}       # js_url -> parsed map
        self.errors = {}
        self.sources = {}    # source name -> set of js files that reference it
        self.sources_content = {}  # source name -> content

    # --------------------------------------------------------
    def parse(self, js_url, source_map_url):
        if not source_map_url:
            return None

        if source_map_url.startswith("data:"):
            try:
                raw = source_map_url.split(",", 1)[1]
                import base64
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
            r = self.session.get(source_map_url, timeout=20)
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
            self.sources.setdefault(src, set()).add(js_url)
        for src, content in zip(
            data.get("sources", []) or [],
            data.get("sourcesContent", []) or []
        ):
            if content and src not in self.sources_content:
                self.sources_content[src] = content

    # --------------------------------------------------------
    def report(self):
        # summarize
        entries = []
        for js_url, data in self.maps.items():
            entries.append({
                "js_file": js_url,
                "sources_count": len(data.get("sources", []) or []),
                "has_content": bool(data.get("sourcesContent")),
                "source_root": data.get("sourceRoot"),
                "file": data.get("file"),
                "first_sources": (data.get("sources") or [])[:10],
            })
        return {
            "maps_parsed": len(self.maps),
            "unique_sources": len(self.sources),
            "sources_with_content": len(self.sources_content),
            "entries": entries,
            "errors": self.errors,
        }


def parse_source_maps(downloads, fetch=True, max_maps=50):
    """
    For each download that has a source_map field, try to fetch + parse.
    Downloads themselves already have `source_map` extracted.
    """
    p = SourceMapParser(fetch=fetch)
    count = 0
    for d in downloads:
        if d.get("status") != 200:
            continue
        sm = d.get("source_map")
        if not sm:
            continue
        if count >= max_maps:
            break
        url = resolve_sourcemap_url(d["url"], sm)
        p.parse(d["url"], url)
        count += 1
    return p
