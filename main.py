#!/usr/bin/env python3
"""
main.py — Mini Scanner Orchestrator
======================================

Runs the checks in scanners.py against every URL in a target file:

  1. CORS misconfiguration
  2. Security headers — missing AND misconfigured (weak values), renders
     PNG + txt evidence if vulnerable
  3. Server banner + dangerous HTTP method disclosure
  4. TRACE method / Cross-Site Tracing (XST) — actively sends TRACE with
     a marker header and checks if it's reflected back
  5. Clickjacking — only runs PoC/screenshot for the FIRST vulnerable
     target; later vulnerable targets are just flagged (no browser/screenshot)

Cross-cutting:
  - Rate limiting (--rate-limit) applies to every outbound request.
  - --token / --header / --cookie let you supply auth upfront.
  - On a 401, the scan pauses once, asks for a token/cookie/header
    interactively, retries that check, and reuses the credential for
    the rest of the run (no more prompting after that).

Requirements:
    pip install requests pillow
    (optional) pip install selenium webdriver-manager   # for clickjack screenshots

Usage:
    python main.py -f urls.txt
    python main.py -f urls.txt --rate-limit 3
    python main.py -f urls.txt --token "eyJhbGciOi..."
    python main.py -f urls.txt --header "X-Api-Key: abc123" --header "X-Custom: val"
    python main.py -f urls.txt --cookie "session=abc123; other=val"
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
    ORANGE = "\033[38;5;208m"
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
# 401 handling
# =====================================================================
def prompt_for_auth() -> dict:
    """Interactively ask for a credential when a 401 is hit. Accepts:
      - a raw token (assumed Bearer)
      - "Header-Name: value" (used verbatim)
    Returns a headers dict (possibly empty if the user skips)."""
    print(c("\n  [!] Received 401 Unauthorized.", C.YELLOW + C.BOLD))
    raw = input(c("      Enter a Bearer token, a full header ('Name: value'), "
                  "or press Enter to skip: ", C.YELLOW)).strip()
    if not raw:
        return {}
    if ":" in raw:
        name, _, value = raw.partition(":")
        return {name.strip(): value.strip()}
    return {"Authorization": f"Bearer {raw}"}


def with_auth_retry(check_fn, url: str, args, auth_state: dict, **kwargs):
    """Call check_fn(url, ..., extra_headers=auth_state['headers']); if the
    result's status_code is 401 and we haven't already asked this run,
    prompt once, merge the credential into auth_state, and retry."""
    result = check_fn(url, extra_headers=auth_state["headers"],
                       rate_limiter=auth_state["rate_limiter"], **kwargs)

    status = getattr(result, "status_code", None)
    if status == 401 and not auth_state["asked"]:
        auth_state["asked"] = True
        new_headers = prompt_for_auth()
        if new_headers:
            auth_state["headers"].update(new_headers)
            print(c("      Retrying with supplied credential...", C.GRAY))
            result = check_fn(url, extra_headers=auth_state["headers"],
                               rate_limiter=auth_state["rate_limiter"], **kwargs)
        else:
            print(c("      No credential supplied — continuing unauthenticated.", C.GRAY))

    return result


# =====================================================================
# Checks
# =====================================================================
def run_cors(url: str, args, auth_state: dict):
    result = with_auth_retry(scanners.check_cors, url, args, auth_state, timeout=args.timeout)
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


def run_security_headers(url: str, args, auth_state: dict):
    result = with_auth_retry(scanners.check_security_headers, url, args, auth_state,
                              timeout=args.timeout, verify=not args.insecure)
    if result.error:
        verdict_line("Security Headers", False, f"error: {result.error}")
        return result

    detail_parts = []
    if result.missing:
        detail_parts.append(f"{len(result.missing)} missing")
    if result.misconfigured:
        detail_parts.append(f"{len(result.misconfigured)} misconfigured")
    detail = ", ".join(detail_parts) if detail_parts else "all present and properly configured"

    verdict_line("Security Headers", result.vulnerable, detail)

    if result.vulnerable:
        for h in result.missing[:6]:
            bullet(f"missing: {h}", C.RED)
        for h, reason in list(result.misconfigured.items())[:6]:
            bullet(f"misconfigured: {h} — {reason}", C.ORANGE)

        out_dir = args.out_dir
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        img_path = f"{out_dir}/evidence_{url.split('//')[-1].replace('/', '_').replace(':', '_')}.png"
        txt_path = img_path.replace(".png", ".txt")
        scanners.render_header_evidence_image(result, img_path)
        scanners.save_header_raw_evidence(result, txt_path)
        print(c(f"        evidence: {img_path}", C.GRAY))

    return result


def run_recon(url: str, args, auth_state: dict):
    methods = with_auth_retry(scanners.check_methods, url, args, auth_state,
                               timeout=args.timeout, active_test=args.active_test)
    banners = with_auth_retry(scanners.check_banners, url, args, auth_state, timeout=args.timeout)

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
            err = scanners.send_through_burp(url, args.burp, timeout=args.timeout, methods=["OPTIONS", "GET"],
                                              extra_headers=auth_state["headers"])
            if err:
                print(c(f"        [!] Burp replay failed: {err}", C.GRAY))
            else:
                print(c(f"        replayed via Burp ({args.burp}) for secondary PoC", C.GRAY))

    return result


def run_trace_xst(url: str, args, auth_state: dict):
    result = with_auth_retry(scanners.check_trace_xst, url, args, auth_state, timeout=args.timeout)
    if result.error:
        verdict_line("TRACE / XST", False, f"error: {result.error}")
        return result

    verdict_line("TRACE / XST", result.vulnerable, result.reason)
    if result.vulnerable:
        path = scanners.save_trace_evidence(result, args.out_dir)
        print(c(f"        evidence: {path}", C.GRAY))
    return result


def run_clickjack(url: str, args, auth_state: dict, state: dict):
    check = with_auth_retry(scanners.check_clickjack_headers, url, args, auth_state, timeout=args.timeout)
    if check.error:
        verdict_line("Clickjacking", False, f"error: {check.error}")
        return check

    verdict_line("Clickjacking", check.vulnerable, check.reason)

    if not check.vulnerable:
        return check

    is_first_encounter = state["screenshot_target"] is None
    take_screenshot = (not args.no_screenshot) and is_first_encounter
    open_browser = is_first_encounter

    poc_result = scanners.run_clickjack_poc(
        url, args.out_dir,
        open_browser=open_browser,
        screenshot=take_screenshot,
    )
    print(c(f"        PoC: {poc_result.poc_path}", C.GRAY))

    if is_first_encounter:
        state["screenshot_target"] = url
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
def process_url(url: str, args, auth_state: dict, state: dict):
    print_target(url)
    run_cors(url, args, auth_state)
    run_security_headers(url, args, auth_state)
    run_recon(url, args, auth_state)
    run_trace_xst(url, args, auth_state)
    run_clickjack(url, args, auth_state, state)


def parse_custom_headers(header_args, token_arg, cookie_arg) -> dict:
    headers = {}
    for h in header_args or []:
        if ":" not in h:
            print(c(f"[!] Ignoring malformed --header value (expected 'Name: value'): {h}", C.YELLOW))
            continue
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()
    if token_arg:
        headers["Authorization"] = f"Bearer {token_arg}"
    if cookie_arg:
        headers["Cookie"] = cookie_arg
    return headers


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
    parser.add_argument("--rate-limit", type=float, default=5.0,
                         help="Max requests per second across all checks (default 5, 0 = unlimited)")
    parser.add_argument("--token", help="Bearer token to send as 'Authorization: Bearer <token>' on every request")
    parser.add_argument("--cookie", help="Raw Cookie header value to send on every request")
    parser.add_argument("--header", action="append",
                         help="Custom header 'Name: value' to send on every request (repeatable)")
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
    print(c(f"[*] Rate limit: {args.rate_limit if args.rate_limit > 0 else 'unlimited'} req/s", C.BLUE))

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

    initial_headers = parse_custom_headers(args.header, args.token, args.cookie)
    if initial_headers:
        print(c(f"[*] Custom headers supplied: {', '.join(initial_headers.keys())}", C.BLUE))

    auth_state = {
        "headers": initial_headers,
        "asked": False,
        "rate_limiter": scanners.RateLimiter(args.rate_limit),
    }
    state = {"screenshot_target": None, "additional_vulnerable": []}

    for url in urls:
        process_url(url, args, auth_state, state)

    print("\n" + c("=" * 70, C.CYAN))
    print(c("[+] Scan complete.", C.CYAN + C.BOLD))
    if state["screenshot_target"]:
        print(c(f"[*] Clickjacking PoC/screenshot captured for: {state['screenshot_target']}", C.CYAN))
    if state["additional_vulnerable"]:
        print(c(f"[!] {len(state['additional_vulnerable'])} additional URL(s) also vulnerable to "
                f"clickjacking (browser/screenshot skipped, PoC HTML still saved for each):", C.YELLOW))
        for u in state["additional_vulnerable"]:
            print(c(f"      - {u}", C.YELLOW))
    print(c("=" * 70, C.CYAN))


if __name__ == "__main__":
    main()
