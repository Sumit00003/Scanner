import requests
import urllib3
from urllib.parse import urlparse
import socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

# Payloads for origin testing
ORIGIN_PAYLOADS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]
# https://example.com.evil.com,
#    https://evil.com#example.com,
#    https://evil.com?example.com,
#    https://sub.example.com.evil.com

# 🔹 Check Burp
def is_burp_running():
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=2)
        s.close()
        return True
    except:
        return False


# 🔹 Save evidence
def save_evidence(url, response, note=""):
    filename = urlparse(url).netloc.replace(":", "_") + "_cors.txt"

    with open(filename, "a") as f:
        f.write(f"\n=== {url} ===\n")
        f.write(f"NOTE: {note}\n")
        f.write("----- RESPONSE HEADERS -----\n")
        for k, v in response.headers.items():
            f.write(f"{k}: {v}\n")

    print(f"[+] Evidence saved: {filename}")


# 🔹 Core CORS check
def check_cors(url, origin=None, use_proxy=False):
    headers = {}

    if origin:
        headers["Origin"] = origin

    try:
        r = requests.get(
            url,
            headers=headers,
            verify=False,
            proxies=PROXY if use_proxy else None,
            timeout=10
        )

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acc = r.headers.get("Access-Control-Allow-Credentials", "")

        return acao, acc, r

    except Exception as e:
        print(f"[!] Error: {e}")
        return "", "", None


# ---------------- MAIN ----------------

if __name__ == "__main__":

    print("[*] Checking Burp Suite connection...")

    if not is_burp_running():
        print("[!] Burp Suite is NOT running on 127.0.0.1:8080")
        exit()
    else:
        print("[+] Burp Suite is running")

    mode = input("\nSelect mode: Fresh (f) or Revalidation (r): ").strip().lower()
    target = input("Enter endpoint: ").strip()

    print(f"\n[+] Testing: {target}")

    vuln_found = False

    # 🔹 1. Wildcard check
    acao, acc, res = check_cors(target)

    if acao == "*":
        print("[!] Wildcard CORS detected")

        if acc.lower() == "true":
            print("[!!!] HIGH RISK: Credentials allowed with wildcard")
            vuln_found = True
        vuln_found = True

    # 🔹 2. Origin reflection + bypass tests
    for payload in ORIGIN_PAYLOADS:
        print(f"\n[*] Testing Origin: {payload}")

        acao, acc, res = check_cors(target, origin=payload)

        if payload == "null" and acao == "null":
            print("[!] NULL origin accepted")

            if acc.lower() == "true":
                print("[!!!] HIGH RISK with credentials")
                vuln_found = True

        elif payload in acao:
            print(f"[!] Origin reflected: {payload}")

            if acc.lower() == "true":
                print("[!!!] HIGH RISK with credentials")
                vuln_found = True

    # ---------------- FRESH ----------------
    if mode == "f":

        if vuln_found:
            print("\n[!] CORS Vulnerability FOUND")

            print("[*] Sending request via Burp for logging...")
            _, _, proxy_res = check_cors(target, origin="https://evil.com", use_proxy=True)

            if proxy_res:
                save_evidence(target, proxy_res, "Fresh - Vulnerable")

        else:
            print("\n[-] No CORS vulnerability found")

    # ---------------- REVALIDATION ----------------
    elif mode == "r":

        if vuln_found:
            print("\n[!] Vulnerability is STILL OPEN")

            print("[*] Sending via Burp...")
            _, _, proxy_res = check_cors(target, origin="https://evil.com", use_proxy=True)

            if proxy_res:
                save_evidence(target, proxy_res, "Revalidation - Still Open")

        else:
            print("\n[+] Vulnerability is CLOSED now")

            print("[*] Sending via Burp for proof...")
            _, _, proxy_res = check_cors(target, origin="https://evil.com", use_proxy=True)

            if proxy_res:
                save_evidence(target, proxy_res, "Revalidation - Closed")

    else:
        print("[!] Invalid mode")