#!/usr/bin/env python3
"""
main.py — Mini Scanner Orchestrator
======================================

Runs the four checks in scanners.py against every URL in a target file:

  1. CORS misconfiguration
  2. Missing security headers  (renders PNG + txt evidence if vulnerable;
     no Burp replay for this check)
  3. Server banner + dangerous HTTP method disclosure (still replayed
     through Burp for secondary PoC when vulnerable)
  4. Clickjacking — ONLY runs the PoC/screenshot step if the target has
     no X-Frame-Options AND no CSP frame-ancestors protection. For the
     FIRST vulnerable target found, opens the PoC in a live browser and
     takes a screenshot. Every subsequent vulnerable target still gets
     its own PoC HTML saved, but the browser/screenshot are skipped —
     it's just flagged as vulnerable in the console.

Console output is intentionally concise: one line per check with a
colored verdict, plus a short list of key findings — not a full header
dump. Full detail always goes to the evidence files on disk.

Requirements:
    pip install requests pillow
    (optional) pip install selenium webdriver-manager   # for clickjack screenshots

Usage:
    python main.py -f urls.txt
    python main.py -f urls.txt --out-dir ./evidence
    python main.py -f urls.txt --no-burp
    python main.py -f urls.txt --active-test     # actively sends dangerous HTTP methods
"""

import argparse
import sys
from pathlib import Path

import scanners


# =====================================================================
# Colors
# =====================================================================
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{C.RESET}"


def print_banner():
    print(c("=" * 70, C.CYAN))
    print(c("                       MINI SCANNER", C.CYAN + C.BOLD))
    print(c("=" * 70, C.CYAN))


def print_target(url: str):
    print("\n" + c("─" * 70, C.GRAY))
    print(c(f"TARGET: ", C.BOLD) + c(url, C.BLUE + C.BOLD))
    print(c("─" * 70, C.GRAY))


def verdict_line(label: str, vulnerable: bool, detail: str = ""):
    tag = c(" VULNERABLE ", C.RED + C.BOLD) if vulnerable else c("   OK   ", C.GREEN + C.BOLD)
    line = f"  [{tag}] {label}"
    if detail:
        line += c(f" — {detail}", C.GRAY)
    print(line)


def bullet(msg: str, color=C.YELLOW):
    print(c(f"        • {msg}", color))


# =====================================================================
# Checks
# =====================================================================
def run_cors(url: str, args):
    result = scanners.check_cors(url, timeout=args.timeout)
    if result.error:
        verdict_line("CORS", False, f"error: {result.error}")
        return result
    if not result.has_cors:
        verdict_line("CORS", False, "no CORS headers present")
        return result

    verdict_line("CORS", result.vulnerable)
    for finding in result.findings[:3]:
        bullet(finding)
    return result


def run_security_headers(url: str, args):
    result = scanners.check_security_headers(url, timeout=args.timeout, verify=not args.insecure)
    if result.error:
        verdict_line("Security Headers", False, f"error: {result.error}")
        return result

    verdict_line("Security Headers", result.vulnerable,
                  f"{len(result.missing)} missing" if result.vulnerable else "all present")

    if result.vulnerable:
        for h in result.missing[:6]:
            bullet(h, C.RED)

        out_dir = args.out_dir
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        img_path = f"{out_dir}/evidence_{url.split('//')[-1].replace('/', '_').replace(':', '_')}.png"
        txt_path = img_path.replace(".png", ".txt")
        scanners.render_header_evidence_image(result, img_path)
        scanners.save_header_raw_evidence(result, txt_path)
        print(c(f"        evidence: {img_path}", C.GRAY))

    return result


def run_recon(url: str, args):
    methods = scanners.check_methods(url, timeout=args.timeout, active_test=args.active_test)
    banners = scanners.check_banners(url, timeout=args.timeout)

    result = scanners.ReconResult(url=url, methods=methods, banners=banners)

    verdict_line("Dangerous Methods", result.has_dangerous_methods,
                  ", ".join(methods.dangerous_advertised) if result.has_dangerous_methods else "none advertised")
    if args.active_test and methods.active_test_results:
        for m, code in methods.active_test_results.items():
            status = "failed" if code == -1 else code
            note = " (ACCEPTED)" if isinstance(status, int) and 200 <= status < 400 else " (rejected)"
            bullet(f"{m}: {status}{note}")

    verdict_line("Banner Disclosure", result.has_banner_disclosure)
    for k, v in list(result.banners.normal_banners.items())[:3]:
        bullet(f"{k}: {v}")
    for k, v in list(result.banners.error_banners.items())[:3]:
        bullet(f"{k}: {v} (leaked on error page)", C.RED)

    if result.vulnerable:
        path = scanners.save_recon_evidence(result, args.out_dir)
        print(c(f"        evidence: {path}", C.GRAY))

        if not args.no_burp:
            err = scanners.send_through_burp(url, args.burp, timeout=args.timeout, methods=["OPTIONS", "GET"])
            if err:
                print(c(f"        [!] Burp replay failed: {err}", C.GRAY))
            else:
                print(c(f"        replayed via Burp ({args.burp}) for secondary PoC", C.GRAY))

    return result


def run_clickjack(url: str, args, state: dict):
    check = scanners.check_clickjack_headers(url, timeout=args.timeout)
    if check.error:
        verdict_line("Clickjacking", False, f"error: {check.error}")
        return check

    verdict_line("Clickjacking", check.vulnerable, check.reason)

    if not check.vulnerable:
        # Protected — per spec, skip PoC/screenshot generation entirely.
        return check

    is_first_encounter = state["screenshot_target"] is None
    take_screenshot = (not args.no_screenshot) and is_first_encounter
    open_browser = is_first_encounter  # only pop the browser once, for the first vulnerable target

    poc_result = scanners.run_clickjack_poc(
        url, args.out_dir,
        open_browser=open_browser,
        screenshot=take_screenshot,
    )
    print(c(f"        PoC: {poc_result.poc_path}", C.GRAY))

    if is_first_encounter:
        state["screenshot_target"] = url  # marks that we've already done the browser+screenshot pass
        if open_browser:
            print(c(f"        opened in browser for live PoC", C.GRAY))
        if take_screenshot:
            if poc_result.screenshot_path:
                print(c(f"        screenshot: {poc_result.screenshot_path}", C.GRAY))
            else:
                print(c("        [!] screenshot not captured (selenium/chromedriver not available)", C.GRAY))
    else:
        state["additional_vulnerable"].append(url)
        print(c(f"        already demonstrated PoC for {state['screenshot_target']} — skipping browser/screenshot "
                f"(one is enough); this target is also vulnerable to clickjacking.", C.YELLOW))

    return check


# =====================================================================
# Driver
# =====================================================================
def process_url(url: str, args, state: dict):
    print_target(url)
    run_cors(url, args)
    run_security_headers(url, args)
    run_recon(url, args)
    run_clickjack(url, args, state)


def main():
    parser = argparse.ArgumentParser(description="Mini Scanner - Automated VAPT Scanner")
    parser.add_argument("-f", "--file", required=True, help="File containing target URLs, one per line")
    parser.add_argument("--out-dir", default="./scan_evidence", help="Directory to save all evidence")
    parser.add_argument("--burp", default="127.0.0.1:8080", help="Burp proxy host:port")
    parser.add_argument("--no-burp", action="store_true", help="Skip replaying vulnerable requests through Burp")
    parser.add_argument("--active-test", action="store_true",
                         help="Actively send dangerous HTTP methods to confirm they're accepted, not just advertised "
                              "(CAUTION: only on authorized scope — can modify/delete data)")
    parser.add_argument("--no-screenshot", action="store_true", help="Don't auto-screenshot the clickjack PoC")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    url_file = Path(args.file).resolve()
    if not url_file.exists():
        print(c(f"[!] File not found: {url_file}", C.RED))
        sys.exit(1)

    with open(url_file) as fh:
        urls = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    if not urls:
        print(c("[!] No URLs found in file.", C.RED))
        sys.exit(1)

    print_banner()
    print(c(f"[*] Targets: {len(urls)}", C.BLUE))
    print(c(f"[*] Evidence directory: {args.out_dir}", C.BLUE))

    if not args.no_burp:
        host, _, port = args.burp.partition(":")
        port = int(port) if port else 8080
        if scanners.is_burp_running(host, port):
            print(c(f"[+] Burp detected on {args.burp}", C.GREEN))
        else:
            print(c(f"[!] Burp not detected on {args.burp} — evidence still generated, "
                    f"Burp-replay steps will just fail per-target.", C.YELLOW))

    if args.active_test:
        print(c("[!] --active-test is ON: dangerous HTTP methods will actually be sent. "
                "Ensure this is authorized scope.", C.YELLOW + C.BOLD))

    state = {"screenshot_target": None, "additional_vulnerable": []}

    for url in urls:
        process_url(url, args, state)

    print("\n" + c("=" * 70, C.CYAN))
    print(c("[+] Scan complete.", C.CYAN + C.BOLD))
    if state["screenshot_target"]:
        print(c(f"[*] Clickjacking screenshot captured for: {state['screenshot_target']}", C.CYAN))
    if state["additional_vulnerable"]:
        print(c(f"[!] {len(state['additional_vulnerable'])} additional URL(s) also vulnerable to "
                f"clickjacking (screenshot skipped, PoC HTML still saved for each):", C.YELLOW))
        for u in state["additional_vulnerable"]:
            print(c(f"      - {u}", C.YELLOW))
    print(c("=" * 70, C.CYAN))


if __name__ == "__main__":
    main()
