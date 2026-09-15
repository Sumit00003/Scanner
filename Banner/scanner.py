"""
scanner.py
Orchestrates: crawl -> download -> retire match -> security pass -> correlate.
Produces a single dict that reporter.py understands.
"""
import os
from urllib.parse import urlparse

from libfinder import (
    get_js_files, download_all,
    extract_domains, detect_graphql,
    detect_websockets, analyze_comments,
    correlate,
)
from security import run_security_analysis
from retire_db import RetireDB
from matcher import VersionMatcher


def _filename(url):
    return os.path.basename(urlparse(url).path)


class Scanner:
    def __init__(self, validate_secrets=True):
        self.db = RetireDB()
        self.matcher = VersionMatcher()
        self.validate_secrets = validate_secrets

    # ---------------------------------------------------------
    def _retire_match(self, js):
        """Try hash -> filename -> content. Return dict or None."""
        hit = self.db.match_hash(js["sha256"])
        if hit:
            return {**hit, "method": "hash"}

        hit = self.db.match_filename(_filename(js["url"]))
        if hit:
            return {**hit, "method": "filename"}

        hit = self.db.match_content(js["text"] or "")
        if hit:
            return {**hit, "method": "filecontent"}

        return None

    # ---------------------------------------------------------
    def _build_library_findings(self, downloads):
        """
        Group identical (library, version, method) into one entry
        with a list of URLs. That's what reporter expects.
        """
        grouped = {}

        for js in downloads:
            if js["status"] != 200:
                continue

            hit = self._retire_match(js)

            if not hit:
                key = ("Unknown", "Unknown", "none")
                grouped.setdefault(key, {
                    "library": "Unknown",
                    "version": "Unknown",
                    "method": "none",
                    "urls": [],
                    "vulnerabilities": [],
                })
                grouped[key]["urls"].append(js["url"])
                continue

            key = (hit["library"], hit["version"], hit["method"])
            if key not in grouped:
                grouped[key] = {
                    "library": hit["library"],
                    "version": hit["version"],
                    "method": hit["method"],
                    "urls": [],
                    "vulnerabilities": hit.get("vulnerabilities", []),
                }
            grouped[key]["urls"].append(js["url"])

        # run matcher per group
        results = []
        for (lib, ver, method), data in grouped.items():
            analysis = self.matcher.analyze(
                data["version"], data["vulnerabilities"]
            )
            results.append({
                "library": lib,
                "version": ver,
                "method": method,
                "status": analysis["status"],
                "severity": analysis["severity"].lower(),
                "count": analysis["count"],
                "findings": analysis["findings"],
                "urls": data["urls"],
            })

        # sort: high severity first
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                 "safe": 4, "unknown": 5}
        results.sort(key=lambda r: order.get(r["severity"], 9))
        return results

    # ---------------------------------------------------------
    def scan(self, url):
        print(f"[+] Crawling {url}")
        js_urls = get_js_files(url)
        print(f"[+] Found {len(js_urls)} JavaScript files")

        if not js_urls:
            return self._empty_report(url)

        print("[+] Downloading...")
        downloads = download_all(js_urls)

        print("[+] Matching against RetireDB...")
        libraries = self._build_library_findings(downloads)

        print("[+] Running security pass (secrets, crypto, endpoints)...")
        sec = run_security_analysis(downloads, validate_secrets=self.validate_secrets)

        print("[+] Extracting domains / GraphQL / WebSockets / comments...")
        domains    = extract_domains(downloads, target=url)
        graphql    = detect_graphql(downloads, base_url=url)
        websockets = detect_websockets(downloads)
        comments   = analyze_comments(downloads)

        print("[+] Correlating...")
        correlation = correlate(
            downloads, libraries,
            secrets=sec["secrets"],
            endpoints=sec["endpoints"],
            domains=domains, comments=comments,
            graphql=graphql, websockets=websockets,
        )

        return {
            "target": url,
            "libraries": libraries,
            "secrets": sec["secrets"].report(),
            "entropy": sec["entropy"].report(),
            "crypto": sec["crypto"].report(),
            "endpoints": sec["endpoints"].report(),
            "domains": domains.report(),
            "graphql": graphql.report(),
            "websockets": websockets.report(),
            "comments": comments.report(),
            "correlation": correlation,
        }

    # ---------------------------------------------------------
    def _empty_report(self, url):
        return {
            "target": url,
            "libraries": [],
            "secrets": {"total": 0, "by_severity": {}, "findings": []},
            "entropy": {"total": 0, "findings": []},
            "crypto": {"files_analyzed": 0, "libraries": [], "algorithms": [],
                       "modes": [], "padding": [], "per_file": []},
            "endpoints": {"total": 0, "endpoints": []},
            "domains": {"domains": [], "ip_addresses": [],
                        "internal_hosts": [], "third_party_hosts": []},
            "graphql": {"endpoints": [], "operations": [], "fragments": [],
                        "introspection_files": [], "files_with_graphql": []},
            "websockets": {"websocket_urls": [], "candidate_paths": [],
                           "constructors": [], "protocols": []},
            "comments": {"total_comments": 0, "interesting": {}, "sample_comments": []},
            "correlation": {"hosts": [], "files": 0, "duplicates": [],
                            "host_libraries": {}, "bundle_families": [],
                            "risky_files": [], "per_file": {}},
        }