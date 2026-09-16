"""
scanner.py
RetireDB + VersionMatcher + Correlator + Scanner + Reporter + CLI.
Entry point: python scanner.py -u https://target.com
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import libfinder as lf


# ============================================================
# RetireDB
# ============================================================

VERSION_CAPTURE = r"([0-9A-Za-z._+\-]+)"


class RetireDB:
    def __init__(self, db_path="data/jsrepository-v6-combined.json"):
        self.filename_patterns = []
        self.filecontent_patterns = []
        self.hashes = {}
        self.library_count = 0

        path = Path(db_path)
        if not path.exists():
            print(f"[!] RetireDB not found at {db_path} -- skipping.")
            return

        with open(path, encoding="utf-8") as f:
            db = json.load(f)

        self.library_count = len(db)
        self._build(db)

    def _compile(self, pattern):
        pattern = pattern.replace("§§version§§", VERSION_CAPTURE)
        try:
            return re.compile(pattern, re.I)
        except re.error:
            return None

    def _build(self, db):
        for library, data in db.items():
            extractors = data.get("extractors", {})
            vulns = data.get("vulnerabilities", [])

            for pat in extractors.get("filename", []):
                rx = self._compile(pat)
                if rx:
                    self.filename_patterns.append({
                        "library": library, "regex": rx, "vulnerabilities": vulns,
                    })
            for pat in extractors.get("filecontent", []):
                rx = self._compile(pat)
                if rx:
                    self.filecontent_patterns.append({
                        "library": library, "regex": rx, "vulnerabilities": vulns,
                    })
            for sha, version in (extractors.get("hashes", {}) or {}).items():
                self.hashes[sha.lower()] = {
                    "library": library, "version": version, "vulnerabilities": vulns,
                }

    def match_hash(self, sha):
        if not sha:
            return None
        return self.hashes.get(sha.lower())

    def match_filename(self, filename):
        if not filename:
            return None
        filename = filename.lower()
        for item in self.filename_patterns:
            m = item["regex"].search(filename)
            if m:
                return {
                    "library": item["library"],
                    "version": m.group(1) if m.lastindex else None,
                    "vulnerabilities": item["vulnerabilities"],
                }
        return None

    def match_content(self, text):
        if not text:
            return None
        for item in self.filecontent_patterns:
            m = item["regex"].search(text)
            if m:
                return {
                    "library": item["library"],
                    "version": m.group(1) if m.lastindex else None,
                    "vulnerabilities": item["vulnerabilities"],
                }
        return None

    def stats(self):
        return {
            "libraries": self.library_count,
            "filename_patterns": len(self.filename_patterns),
            "filecontent_patterns": len(self.filecontent_patterns),
            "hashes": len(self.hashes),
        }


# ============================================================
# VersionMatcher
# ============================================================

def _parse_version(v):
    if not v:
        return None
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v))
    if not m:
        return None
    return tuple(int(x) if x else 0 for x in m.groups())


def _in_range(version, ranges):
    v = _parse_version(version)
    if not v:
        return False
    for r in ranges or []:
        below = _parse_version(r.get("below"))
        at_or_above = _parse_version(r.get("atOrAbove"))
        if below and v >= below:
            continue
        if at_or_above and v < at_or_above:
            continue
        return True
    return False


class VersionMatcher:
    def analyze(self, version, vulnerabilities):
        findings = []
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        worst = "safe"
        worst_rank = 99

        for v in vulnerabilities or []:
            ranges = v.get("below") or v.get("atOrAbove") or []
            # RetireDB format: {"below": "1.2.3", "severity": "high", ...}
            if isinstance(ranges, str):
                ranges = [{"below": ranges}]
            if not _in_range(version, ranges):
                continue

            sev = (v.get("severity") or "medium").lower()
            findings.append({
                "summary": v.get("identifiers", {}).get("summary")
                           or v.get("summary") or "Known vulnerability",
                "severity": sev,
                "cwe": v.get("cwe") or [],
                "identifiers": v.get("identifiers", {}),
            })
            rank = sev_rank.get(sev, 5)
            if rank < worst_rank:
                worst_rank, worst = rank, sev

        return {
            "status": "VULNERABLE" if findings else "SAFE",
            "severity": worst,
            "count": len(findings),
            "findings": findings,
        }


# ============================================================
# Correlator
# ============================================================

def _host(url):
    from urllib.parse import urlparse
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


class Correlator:
    def __init__(self, recon, libraries):
        self.recon = recon
        self.libraries = libraries
        self.per_file = defaultdict(dict)
        self.by_hash = defaultdict(list)

    def run(self):
        self._index_downloads()
        self._index_libraries()
        self._index_secrets()
        self._index_entropy()
        self._index_endpoints()
        self._index_domains()
        self._index_comments()
        self._index_crypto()
        return self._report()

    def _index_downloads(self):
        for d in self.recon["downloads"]:
            if d.get("status") != 200:
                continue
            url = d["url"]
            self.by_hash[d["sha256"]].append(url)
            self.per_file[url].update({
                "size": d.get("size"),
                "sha256": d.get("sha256"),
                "has_source_map": bool(d.get("source_map")),
                "has_banner": bool(d.get("banner")),
            })

    def _index_libraries(self):
        for lib in self.libraries:
            for u in lib.get("urls", []):
                self.per_file[u].setdefault("libraries", []).append({
                    "name": lib["library"], "version": lib["version"],
                    "severity": lib["severity"],
                })

    def _index_secrets(self):
        s = self.recon.get("secrets")
        if not s:
            return
        for item in getattr(s, "findings", []):
            url = item["file"]
            self.per_file[url].setdefault("secrets", []).append({
                "type": item["type"], "severity": item["severity"],
                "validated": item.get("validated"), "masked": item.get("masked"),
                "line": item.get("line"),
            })

    def _index_entropy(self):
        e = self.recon.get("entropy")
        if not e:
            return
        for item in getattr(e, "findings", []):
            self.per_file[item["file"]].setdefault("entropy", []).append({
                "entropy": item.get("entropy"), "masked": item.get("masked"),
                "line": item.get("line"),
            })

    def _index_crypto(self):
        c = self.recon.get("crypto")
        if not c:
            return
        for entry in getattr(c, "findings", []):
            url = entry.get("file")
            if not url:
                continue
            libs  = sorted({x["type"] for x in entry.get("libraries", [])})
            algos = sorted({x["type"] for x in entry.get("algorithms", [])})
            if libs or algos:
                self.per_file[url]["crypto"] = {"libraries": libs, "algorithms": algos}

    def _index_endpoints(self):
        e = self.recon.get("endpoints")
        if not e:
            return
        rep = e.report() if hasattr(e, "report") else e
        for item in rep.get("endpoints", []):
            for u in item.get("found_in", []):
                self.per_file[u].setdefault("endpoints", []).append({
                    "endpoint": item["endpoint"], "type": item["type"],
                    "confidence": item["confidence"],
                })

    def _index_domains(self):
        d = self.recon.get("domains")
        if not d:
            return
        rep = d.report() if hasattr(d, "report") else d
        for entry in rep.get("domains", []):
            for f in entry.get("found_in", []):
                self.per_file[f].setdefault("domains", []).append(entry["domain"])

    def _index_comments(self):
        c = self.recon.get("comments")
        if not c:
            return
        rep = c.report() if hasattr(c, "report") else c
        for tag, hits in rep.get("interesting", {}).items():
            for h in hits:
                self.per_file[h["file"]].setdefault("comment_flags", []).append(tag)

    def _report(self):
        duplicates = {h: urls for h, urls in self.by_hash.items() if len(urls) > 1}

        host_libs = defaultdict(set)
        for url, info in self.per_file.items():
            for lib in info.get("libraries", []):
                host_libs[_host(url)].add(f"{lib['name']}@{lib['version']}")

        families = defaultdict(list)
        for url in self.per_file:
            from urllib.parse import urlparse
            path = urlparse(url).path
            base = (path.rsplit("/", 1)[-1] or path).split(".")[0]
            families[(_host(url), base)].append(url)

        risky = []
        for url, info in self.per_file.items():
            score = 0
            for s in info.get("secrets", []):
                w = {"HIGH": 10, "MEDIUM": 5, "LOW": 2}.get(
                    (s.get("severity") or "").upper(), 1)
                if s.get("validated") is True:
                    w *= 2
                score += w
            score += len(info.get("comment_flags", []))
            score += 2 if info.get("has_source_map") else 0
            score += len(info.get("entropy", []))
            for lib in info.get("libraries", []):
                score += {"critical": 8, "high": 5, "medium": 3,
                          "low": 1}.get(lib.get("severity"), 0)
            if score:
                risky.append({
                    "url": url, "score": score,
                    "flags": {
                        "secrets": len(info.get("secrets", [])),
                        "entropy": len(info.get("entropy", [])),
                        "comments": info.get("comment_flags", []),
                        "has_source_map": info.get("has_source_map", False),
                        "crypto": info.get("crypto", {}),
                    },
                })
        risky.sort(key=lambda r: -r["score"])

        return {
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


# ============================================================
# Scanner
# ============================================================

class Scanner:
    def __init__(self, db_path="data/jsrepository-v6-combined.json",
                 validate_secrets=True, fetch_source_maps=True):
        self.db = RetireDB(db_path)
        self.matcher = VersionMatcher()
        self.validate_secrets = validate_secrets
        self.fetch_source_maps = fetch_source_maps

    def _match_download(self, js):
        for method, hit in (
            ("hash",        self.db.match_hash(js["sha256"])),
            ("filename",    self.db.match_filename(_basename(js["url"]))),
            ("filecontent", self.db.match_content(js["text"] or "")),
        ):
            if hit:
                return {**hit, "method": method}
        return None

    def scan(self, url):
        print(f"[+] Crawling {url}")
        recon = lf.run_recon(
            url,
            validate_secrets=self.validate_secrets,
            fetch_source_maps=self.fetch_source_maps,
        )

        if not recon["js_files"]:
            print("[!] No JS files found.")
            return self._empty(url)

        print(f"[+] Found {len(recon['js_files'])} JS files")

        # group retire hits
        grouped = {}
        for js in recon["downloads"]:
            if js["status"] != 200:
                continue
            hit = self._match_download(js)
            if not hit:
                key = ("Unknown", "Unknown", "none")
                grouped.setdefault(key, {
                    "library": "Unknown", "version": "Unknown",
                    "method": "none", "urls": [], "vulnerabilities": [],
                })
                grouped[key]["urls"].append(js["url"])
                continue
            key = (hit["library"], hit["version"], hit["method"])
            grouped.setdefault(key, {
                "library": hit["library"], "version": hit["version"],
                "method": hit["method"], "urls": [],
                "vulnerabilities": hit.get("vulnerabilities", []),
            })
            grouped[key]["urls"].append(js["url"])

        libraries = []
        for (lib, ver, method), data in grouped.items():
            analysis = self.matcher.analyze(data["version"], data["vulnerabilities"])
            libraries.append({
                "library": lib, "version": ver, "method": method,
                "status": analysis["status"],
                "severity": analysis["severity"].lower(),
                "count": analysis["count"],
                "findings": analysis["findings"],
                "urls": data["urls"],
            })

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                 "safe": 4, "unknown": 5}
        libraries.sort(key=lambda r: order.get(r["severity"], 9))

        print("[+] Correlating...")
        correlation = Correlator(recon, libraries).run()

        return self._package(recon, libraries, correlation)

    def _package(self, recon, libraries, correlation):
        rep = lambda x: x.report() if hasattr(x, "report") else x
        return {
            "target": recon["target"],
            "js_files": recon["js_files"],
            "libraries": libraries,
            "secrets":   rep(recon["secrets"]),
            "entropy":   rep(recon["entropy"]),
            "crypto":    rep(recon["crypto"]),
            "endpoints": rep(recon["endpoints"]),
            "domains":   rep(recon["domains"]),
            "graphql":   rep(recon["graphql"]),
            "websockets":rep(recon["websockets"]),
            "comments":  rep(recon["comments"]),
            "call_graph": rep(recon["call_graph"]) if recon.get("call_graph") else None,
            "source_maps": rep(recon["source_maps"]) if recon.get("source_maps") else None,
            "correlation": correlation,
            "retire_stats": self.db.stats(),
        }

    def _empty(self, url):
        return {
            "target": url, "js_files": [], "libraries": [],
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
            "call_graph": None, "source_maps": None,
            "correlation": {"files": 0, "duplicates": [], "host_libraries": {},
                            "bundle_families": [], "risky_files": [], "per_file": {}},
            "retire_stats": self.db.stats(),
        }


def _basename(url):
    from urllib.parse import urlparse
    import os
    return os.path.basename(urlparse(url).path)


# ============================================================
# Reporter
# ============================================================

class Reporter:
    def __init__(self, console=None):
        self.console = console or Console()

    def summary(self, report):
        libs = report["libraries"]
        counts = {"critical": 0, "high": 0, "medium": 0,
                  "low": 0, "safe": 0, "unknown": 0}
        for lib in libs:
            counts[lib["severity"]] = counts.get(lib["severity"], 0) + 1

        t = Table(title="Scan Summary")
        t.add_column("Metric")
        t.add_column("Value", justify="right")
        t.add_row("Target",       report["target"])
        t.add_row("JS files",     str(len(report["js_files"])))
        t.add_row("Libraries",    str(len(libs)))
        t.add_row("Critical",     str(counts["critical"]))
        t.add_row("High",         str(counts["high"]))
        t.add_row("Medium",       str(counts["medium"]))
        t.add_row("Low",          str(counts["low"]))
        t.add_row("Safe",         str(counts["safe"]))
        t.add_row("Unknown",      str(counts["unknown"]))
        t.add_row("Secrets",      str(report["secrets"]["total"]))
        t.add_row("Endpoints",    str(report["endpoints"]["total"]))
        t.add_row("Domains",      str(len(report["domains"]["domains"])))
        t.add_row("Risky Files",  str(len(report["correlation"]["risky_files"])))
        self.console.print(t)

    def console_report(self, report):
        self.summary(report)

        for lib in report["libraries"]:
            body = [
                f"Version : {lib['version']}",
                f"Status  : {lib['status']}",
                f"Severity: {lib['severity'].upper()}",
                f"Method  : {lib['method']}",
                f"URLs    : {len(lib['urls'])}",
                "", "Locations:",
            ]
            for u in lib["urls"][:10]:
                body.append(f"  • {u}")
            if len(lib["urls"]) > 10:
                body.append(f"  … +{len(lib['urls']) - 10} more")
            if lib["findings"]:
                body.append("")
                body.append("Vulnerabilities:")
                for v in lib["findings"]:
                    body.append(f"  • [{v['severity'].upper()}] {v['summary']}")
                    if v.get("cwe"):
                        body.append(f"     CWE: {', '.join(v['cwe'])}")
            self.console.print(Panel(
                "\n".join(body), title=lib["library"],
                border_style=self._color(lib["severity"]),
            ))

        s = report["secrets"]
        if s["total"]:
            lines = []
            for f in s["findings"][:30]:
                mark = "✓" if f.get("validated") is True else \
                       "✗" if f.get("validated") is False else " "
                lines.append(f"[{mark}] [{f['severity']:<6}] {f['type']:<22} "
                             f"{f['masked']}  @ {f['file'].split('/')[-1]}:{f['line']}")
            self.console.print(Panel(
                "\n".join(lines),
                title=f"Secrets ({s['total']})  {s['by_severity']}",
                border_style="red",
            ))

        e = report["endpoints"]
        if e["total"]:
            self.console.print(Panel(
                "\n".join(f"[{x['type']:<9}] {x['confidence']:>3}  {x['endpoint']}"
                          for x in e["endpoints"][:30]),
                title=f"Endpoints ({e['total']})", border_style="cyan",
            ))

        d = report["domains"]
        if d["domains"]:
            self.console.print(Panel(
                "\n".join(f"[{x['relationship']:<11}] {x['domain']}  "
                          f"({len(x['hosts'])} hosts, {len(x['found_in'])} files)"
                          for x in d["domains"][:30]),
                title=f"Domains ({len(d['domains'])})", border_style="blue",
            ))

        g = report["graphql"]
        if g["endpoints"] or g["operations"]:
            lines = [f"endpoint: {x['url']}" for x in g["endpoints"]]
            lines += [f"{o['type']:<10} {o['name']}" for o in g["operations"]]
            if g["introspection_files"]:
                lines.append(f"[!] Introspection in {len(g['introspection_files'])} file(s)")
            self.console.print(Panel("\n".join(lines),
                                     title="GraphQL", border_style="magenta"))

        w = report["websockets"]
        if w["websocket_urls"] or w["constructors"]:
            lines = [f"url: {x['url']}" for x in w["websocket_urls"]]
            lines += [f"{c['kind']:<12} in {c['file'].split('/')[-1]}"
                      for c in w["constructors"][:10]]
            if w["protocols"]:
                lines.append(f"protocols: {', '.join(w['protocols'])}")
            self.console.print(Panel("\n".join(lines),
                                     title="WebSockets / SSE",
                                     border_style="yellow"))

        c = report["crypto"]
        if c["libraries"] or c["algorithms"]:
            self.console.print(Panel(
                f"libraries : {', '.join(c['libraries']) or '-'}\n"
                f"algorithms: {', '.join(c['algorithms']) or '-'}\n"
                f"modes     : {', '.join(c['modes']) or '-'}\n"
                f"padding   : {', '.join(c['padding']) or '-'}",
                title="Crypto Usage", border_style="green",
            ))

        r = report["correlation"]["risky_files"]
        if r:
            self.console.print(Panel(
                "\n".join(f"score={x['score']:<3} {x['url']}" for x in r[:20]),
                title="Risky Files", border_style="red",
            ))

    def _color(self, sev):
        return {"critical": "red", "high": "red", "medium": "yellow",
                "low": "blue", "safe": "green"}.get(sev.lower(), "white")

    # --- exports ---
    def export_json(self, report, filename="report.json"):
        Path(filename).write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8")
        self.console.print(f"[+] JSON -> {filename}")

    def export_csv(self, report, filename="report.csv"):
        with open(filename, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Library", "Version", "Severity",
                        "Status", "Method", "Occurrences", "URLs"])
            for lib in report["libraries"]:
                w.writerow([lib["library"], lib["version"], lib["severity"],
                            lib["status"], lib["method"], len(lib["urls"]),
                            " | ".join(lib["urls"])])
        self.console.print(f"[+] CSV  -> {filename}")

    def export_markdown(self, report, filename="report.md"):
        L = [f"# JS Recon — {report['target']}", ""]
        L.append("## Libraries")
        for lib in report["libraries"]:
            L.append(f"### {lib['library']} {lib['version']}")
            L.append(f"- Severity: **{lib['severity']}**")
            L.append(f"- Status: {lib['status']}")
            L.append(f"- Method: {lib['method']}")
            L.append(f"- Occurrences: {len(lib['urls'])}")
            if lib["findings"]:
                L.append("- Vulnerabilities:")
                for v in lib["findings"]:
                    L.append(f"  - [{v['severity']}] {v['summary']}")
            L.append("")

        s = report["secrets"]
        if s["total"]:
            L.append(f"## Secrets ({s['total']})")
            for f in s["findings"]:
                L.append(f"- **{f['severity']}** `{f['type']}` — `{f['masked']}` "
                         f"@ `{f['file']}:{f['line']}`")
            L.append("")

        e = report["endpoints"]
        if e["total"]:
            L.append(f"## Endpoints ({e['total']})")
            for x in e["endpoints"]:
                L.append(f"- `[{x['type']}]` {x['endpoint']}")
            L.append("")

        d = report["domains"]
        if d["domains"]:
            L.append(f"## Domains ({len(d['domains'])})")
            for x in d["domains"]:
                L.append(f"- **{x['relationship']}** — {x['domain']}")
            L.append("")

        Path(filename).write_text("\n".join(L), encoding="utf-8")
        self.console.print(f"[+] MD   -> {filename}")


# ============================================================
# CLI
# ============================================================

def main():
    p = argparse.ArgumentParser(description="LibFinder - JS recon toolkit")
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument("--db", default="data/jsrepository-v6-combined.json",
                   help="Path to RetireDB JSON")
    p.add_argument("--json", help="Write JSON report")
    p.add_argument("--csv",  help="Write CSV report")
    p.add_argument("--md",   help="Write Markdown report")
    p.add_argument("--no-validate-secrets", action="store_true")
    p.add_argument("--no-source-maps", action="store_true")
    args = p.parse_args()

    print("=" * 60)
    print(" LibFinder - JavaScript Recon Toolkit")
    print("=" * 60)

    scanner = Scanner(
        db_path=args.db,
        validate_secrets=not args.no_validate_secrets,
        fetch_source_maps=not args.no_source_maps,
    )
    report = scanner.scan(args.url)

    rep = Reporter()
    rep.console_report(report)

    if args.json: rep.export_json(report, args.json)
    if args.csv:  rep.export_csv(report, args.csv)
    if args.md:   rep.export_markdown(report, args.md)


if __name__ == "__main__":
    main()
