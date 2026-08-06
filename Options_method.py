import requests
import urllib3
import socket
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

REVIEW_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]


# ----------------------------------------------------
# Check Burp
# ----------------------------------------------------
def is_burp_running():
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=2)
        s.close()
        return True
    except Exception:
        return False


# ----------------------------------------------------
# Send OPTIONS request
# ----------------------------------------------------
def options_request(url, proxy=False):

    try:
        response = requests.options(
            url,
            verify=False,
            timeout=10,
            proxies=PROXY if proxy else None
        )

        return response

    except Exception as e:
        print(f"[-] Request Failed : {e}")
        return None


# ----------------------------------------------------
# Analyse Response
# ----------------------------------------------------
def analyse(response):

    status = response.status_code

    allow = response.headers.get("Allow")
    dav = response.headers.get("DAV")

    options_enabled = False
    advertised_methods = []
    review = []

    if allow:
        advertised_methods = [
            x.strip().upper()
            for x in allow.split(",")
        ]

        if "OPTIONS" in advertised_methods:
            options_enabled = True

        review = [
            m for m in REVIEW_METHODS
            if m in advertised_methods
        ]

    return {
        "status": status,
        "allow": allow,
        "options_enabled": options_enabled,
        "methods": advertised_methods,
        "review": review,
        "dav": dav
    }


# ----------------------------------------------------
# Save Evidence
# ----------------------------------------------------
def save_headers(url, response):

    filename = urlparse(url).netloc.replace(":", "_") + "_options_headers.txt"

    with open(filename, "a", encoding="utf-8") as f:

        f.write(f"\n{'='*70}\n")
        f.write(url + "\n")
        f.write(f"Status: {response.status_code}\n\n")

        for k, v in response.headers.items():
            f.write(f"{k}: {v}\n")

    print(f"[+] Evidence saved -> {filename}")


# ----------------------------------------------------
# Print Result
# ----------------------------------------------------
def report(url, result):

    print("\n" + "="*70)
    print("OPTIONS METHOD ASSESSMENT")
    print("="*70)

    print(f"Target              : {url}")
    print(f"Status Code         : {result['status']}")

    print()

    if result["allow"]:
        print(f"Allow Header        : {result['allow']}")
    else:
        print("Allow Header        : Not Present")

    print()

    if result["options_enabled"]:
        print("[+] OPTIONS Method  : Enabled")
    else:
        print("[-] OPTIONS Method  : Not Explicitly Advertised")

    if result["methods"]:
        print("\nAdvertised Methods")
        print("------------------")
        for m in result["methods"]:
            print(f"  - {m}")

    if result["review"]:
        print("\nMethods Requiring Manual Verification")
        print("-------------------------------------")
        for m in result["review"]:
            print(f"  - {m}")

    if result["dav"]:
        print("\nWebDAV Header")
        print("-------------")
        print(result["dav"])

    print("\nAssessment")

    if result["options_enabled"]:
        print("✓ Endpoint responds to OPTIONS.")
    else:
        print("• OPTIONS is not explicitly advertised via the Allow header.")

    if result["review"]:
        print("• One or more methods should be manually verified for appropriate authentication and authorization.")

    print("="*70)


# ----------------------------------------------------
# Main
# ----------------------------------------------------
def main():

    print("[*] Checking Burp Suite...")

    if not is_burp_running():
        print("[-] Burp Suite not detected on 127.0.0.1:8080")
        return

    print("[+] Burp detected.")

    url = input("\nTarget URL: ").strip()

    print("\n[*] Sending OPTIONS request...")

    response = options_request(url)

    if response is None:
        return

    result = analyse(response)

    report(url, result)

    print("\n[*] Sending request through Burp for evidence...")

    proxy_response = options_request(url, proxy=True)

    if proxy_response:
        save_headers(url, proxy_response)


if __name__ == "__main__":
    main()
