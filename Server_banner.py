import requests
import urllib3
from urllib.parse import urlparse
import socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}


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
    filename = urlparse(url).netloc.replace(":", "_") + "_banner.txt"

    with open(filename, "a") as f:
        f.write(f"\n=== {url} ===\n")
        f.write(f"NOTE: {note}\n")
        f.write(f"Status Code: {response.status_code}\n")
        f.write("----- RESPONSE HEADERS -----\n")
        for k, v in response.headers.items():
            f.write(f"{k}: {v}\n")

    print(f"[+] Evidence saved: {filename}")


# 🔹 Extract banner
def extract_banner(response):
    server = response.headers.get("Server")
    powered = response.headers.get("X-Powered-By")

    banners = []

    if server:
        banners.append(f"Server: {server}")

    if powered:
        banners.append(f"X-Powered-By: {powered}")

    return banners


# 🔹 Normal request
def normal_check(url, use_proxy=False):
    try:
        r = requests.get(
            url,
            verify=False,
            proxies=PROXY if use_proxy else None,
            timeout=20
        )
        return r
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


# 🔹 Force error (try to trigger 500)
def error_check(url, use_proxy=False):
    try:
        # Sending malformed headers & params
        r = requests.get(
            url,
            headers={
                "X-Invalid-Header": "\x00\x01\x02",
                "Content-Length": "999999999"
            },
            params={"test": "'\"<script>"},
            verify=False,
            proxies=PROXY if use_proxy else None,
            timeout=10
        )
        return r
    except Exception as e:
        print(f"[!] Error (expected sometimes): {e}")
        return None


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

    # 🔹 1. Normal request
    response = normal_check(target)

    if response:
        banners = extract_banner(response)

        if banners:
            print("[!] Server Banner Found:")
            for b in banners:
                print(f"    {b}")
            vuln_found = True
        else:
            print("[-] No banner in normal response")

    # 🔹 2. Error-based check
    print("\n[*] Triggering error response...")

    error_response = error_check(target)

    if error_response:
        print(f"[*] Status Code: {error_response.status_code}")

        if error_response.status_code >= 500:
            banners = extract_banner(error_response)

            if banners:
                print("[!] Banner found in error response:")
                for b in banners:
                    print(f"    {b}")
                vuln_found = True
            else:
                print("[-] No banner in error response")

    # ---------------- FRESH ----------------
    if mode == "f":

        if vuln_found:
            print("\n[!] Banner Disclosure FOUND")

            print("[*] Sending request via Burp...")
            proxy_res = normal_check(target, use_proxy=True)

            if proxy_res:
                save_evidence(target, proxy_res, "Fresh - Banner Found")

        else:
            print("\n[-] No banner disclosure found")

    # ---------------- REVALIDATION ----------------
    elif mode == "r":

        if vuln_found:
            print("\n[!] Vulnerability is STILL OPEN")

            print("[*] Sending via Burp...")
            proxy_res = normal_check(target, use_proxy=True)

            if proxy_res:
                save_evidence(target, proxy_res, "Revalidation - Still Open")

        else:
            print("\n[+] Vulnerability is CLOSED now")

            print("[*] Sending via Burp for proof...")
            proxy_res = normal_check(target, use_proxy=True)

            if proxy_res:
                save_evidence(target, proxy_res, "Revalidation - Closed")

    else:
        print("[!] Invalid mode")