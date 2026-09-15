"""
reporter.py
Renders the Scanner.scan() report as console / JSON / CSV / Markdown.
Only shows sections that have content.
"""
import csv
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown


class Reporter:
    def __init__(self, console=None):
        self.console = console or Console()

    # =========================================================
    # CONSOLE
    # =========================================================

    def summary(self, report):
        libs = report["libraries"]
        counts = {"critical": 0, "high": 0, "medium": 0,
                  "low": 0, "safe": 0, "unknown": 0}
        for lib in libs:
            counts[lib["severity"]] = counts.get(lib["severity"], 0) + 1

        t = Table(title="Scan Summary")
        t.add_column("Metric")
        t.add_column("Value", justify="right")

        t.add_row("Target",        report["target"])
        t.add_row("Libraries",     str(len(libs)))
        t.add_row("Critical",      str(counts["critical"]))
        t.add_row("High",          str(counts["high"]))
        t.add_row("Medium",        str(counts["medium"]))
        t.add_row("Low",           str(counts["low"]))
        t.add_row("Safe",          str(counts["safe"]))
        t.add_row("Unknown",       str(counts["unknown"]))
        t.add_row("Secrets",       str(report["secrets"]["total"]))
        t.add_row("Endpoints",     str(report["endpoints"]["total"]))
        t.add_row("Domains",       str(len(report["domains"]["domains"])))
        t.add_row("Risky Files",   str(len(report["correlation"]["risky_files"])))

        self.console.print(t)

    # ---------------------------------------------------------
    def console_report(self, report):
        self.summary(report)

        # --- Libraries ---
        for lib in report["libraries"]:
            body = [
                f"Version : {lib['version']}",
                f"Status  : {lib['status']}",
                f"Severity: {lib['severity'].upper()}",
                f"Method  : {lib['method']}",
                f"URLs    : {len(lib['urls'])}",
                "",
                "Locations:",
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
                "\n".join(body),
                title=lib["library"],
                border_style=self._sev_color(lib["severity"]),
            ))

        # --- Secrets ---
        s = report["secrets"]
        if s["total"]:
            self.console.print(Panel(
                "\n".join(
                    f"[{f['severity']:<6}] {f['type']:<24} {f['masked']}"
                    f"  @ {f['file'].split('/')[-1]}:{f['line']}"
                    for f in s["findings"][:30]
                ) or "(none)",
                title=f"Secrets ({s['total']})  {s['by_severity']}",
                border_style="red",
            ))

        # --- Endpoints ---
        e = report["endpoints"]
        if e["total"]:
            self.console.print(Panel(
                "\n".join(
                    f"[{x['type']:<9}] {x['confidence']:>3}  {x['endpoint']}"
                    for x in e["endpoints"][:30]
                ),
                title=f"Endpoints ({e['total']})",
                border_style="cyan",
            ))

        # --- Domains ---
        d = report["domains"]
        if d["domains"]:
            self.console.print(Panel(
                "\n".join(
                    f"[{x['relationship']:<11}] {x['domain']}  "
                    f"({len(x['hosts'])} hosts, {len(x['found_in'])} files)"
                    for x in d["domains"][:30]
                ),
                title=f"Domains ({len(d['domains'])})",
                border_style="blue",
            ))

        # --- GraphQL ---
        g = report["graphql"]
        if g["endpoints"] or g["operations"]:
            lines = [f"endpoint: {x['url']}" for x in g["endpoints"]]
            lines += [f"{o['type']:<10} {o['name']}" for o in g["operations"]]
            if g["introspection_files"]:
                lines.append(f"[!] Introspection strings in "
                             f"{len(g['introspection_files'])} file(s)")
            self.console.print(Panel("\n".join(lines),
                                     title="GraphQL", border_style="magenta"))

        # --- WebSockets ---
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

        # --- Crypto ---
        c = report["crypto"]
        if c["libraries"] or c["algorithms"]:
            self.console.print(Panel(
                f"libraries : {', '.join(c['libraries']) or '-'}\n"
                f"algorithms: {', '.join(c['algorithms']) or '-'}\n"
                f"modes     : {', '.join(c['modes']) or '-'}\n"
                f"padding   : {', '.join(c['padding']) or '-'}",
                title="Crypto Usage", border_style="green",
            ))

        # --- Risky files ---
        r = report["correlation"]["risky_files"]
        if r:
            self.console.print(Panel(
                "\n".join(f"score={x['score']:<3} {x['url']}" for x in r[:20]),
                title="Risky Files", border_style="red",
            ))

    # ---------------------------------------------------------
    def _sev_color(self, sev):
        return {
            "critical": "red", "high": "red",
            "medium": "yellow", "low": "blue",
            "safe": "green", "unknown": "dim",
        }.get(sev.lower(), "white")

    # =========================================================
    # EXPORTS
    # =========================================================

    def export_json(self, report, filename="report.json"):
        Path(filename).write_text(
            json.dumps(report, indent=2, default=str),
            encoding="utf-8",
        )
        self.console.print(f"[+] JSON  -> {filename}")

    def export_csv(self, report, filename="report.csv"):
        with open(filename, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Library", "Version", "Severity",
                        "Status", "Method", "Occurrences", "URLs"])
            for lib in report["libraries"]:
                w.writerow([
                    lib["library"], lib["version"], lib["severity"],
                    lib["status"], lib["method"], len(lib["urls"]),
                    " | ".join(lib["urls"]),
                ])
        self.console.print(f"[+] CSV   -> {filename}")

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
        self.console.print(f"[+] MD    -> {filename}")