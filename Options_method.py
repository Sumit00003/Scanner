import requests
import urllib3
from urllib.parse import urlparse
import socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]


# 🔹 Check if Burp is running
def is_burp_running():
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=2)
        s.close()
        return True
    except:
        return False


# 🔹 Core check (no proxy by default)
def check_options(url, use_proxy=False):
    try:
        response = requests.options(
            url,
            verify=False,
            proxies=PROXY if use_proxy else None,
            timeout=10
        )

        allow = response.headers.get("Allow")

        if allow:
            methods = allow.upper()
            risky = [m for m in DANGEROUS_METHODS if m in methods]

            return True, allow, risky, response
        else:
            return False, None, [], response

    except Exception as e:
        print(f"[!] Error: {e}")
        return False, None, [], None


# 🔹 Save response evidence
def save_evidence(url, response):
    filename = urlparse(url).netloc.replace(":", "_") + "_evidence.txt"

    with open(filename, "a") as f:
        f.write(f"\n=== {url} ===\n")
        f.write("----- RESPONSE HEADERS -----\n")
        for k, v in response.headers.items():
            f.write(f"{k}: {v}\n")

    print(f"[+] Evidence saved: {filename}")


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

    vuln, allow, risky, response = check_options(target, use_proxy=False)

    # ---------------- FRESH ----------------
    if mode == "f":

        if vuln and risky:
            print(f"[!] Vulnerability FOUND")
            print(f"    Allow: {allow}")

            # Send again through Burp
            print("[*] Sending request through Burp for logging...")
            _, _, _, proxy_response = check_options(target, use_proxy=True)

            if proxy_response:
                save_evidence(target, proxy_response)

        else:
            print("[-] No vulnerability found")

    # ---------------- REVALIDATION ----------------
    elif mode == "r":

        if vuln and risky:
            print("[!] Vulnerability is STILL OPEN")
            print(f"    Allow: {allow}")

            print("[*] Sending request through Burp...")
            _, _, _, proxy_response = check_options(target, use_proxy=True)

            if proxy_response:
                save_evidence(target, proxy_response)

        else:
            print("[+] Vulnerability is CLOSED now")

            print("[*] Sending request through Burp for proof...")
            _, _, _, proxy_response = check_options(target, use_proxy=True)

            if proxy_response:
                save_evidence(target, proxy_response)

    else:
        print("[!] Invalid mode selected (use 'f' or 'r')")