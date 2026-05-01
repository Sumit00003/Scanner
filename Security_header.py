import os
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import urllib3
import socket

from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

SEC_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

visited = set()

# 🔹 Burp Check
def is_burp_running():
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=2)
        s.close()
        return True
    except:
        return False


# 🔹 Save Evidence
'''def save_evidence(url, response, note=""):
    filename = urlparse(url).netloc.replace(":", "_") + "_sec_headers.txt"

    with open(filename, "a") as f:
        f.write(f"\n=== {url} ===\n")
        f.write(f"NOTE: {note}\n")
        f.write("----- HEADERS -----\n")
        for k, v in response.headers.items():
            f.write(f"{k}: {v}\n")

    print(f"[+] Evidence saved: {filename}")'''


# 🔹 LLM Setup
llm = ChatGroq(
    groq_api_key="key",
    model="llama-3.1-8b-instant"
)

prompt = ChatPromptTemplate.from_template("""
You are a penetration tester.

Check if these security headers are properly configured:
{headers}

Reply shortly:
- Secure / Misconfigured
- Reason
""")

def validate_ai(headers):
    chain = prompt | llm
    return chain.invoke({"headers": headers}).content

headers = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}

# 🔹 Get Headers
def get_headers(url, use_proxy=False):
    try:
        r = requests.get(
            url,
            headers=headers,
            verify=False,
            proxies=PROXY if use_proxy else None,
            timeout=10
        )

        extracted = {}
        missing = []

        for h in SEC_HEADERS:
            if h in r.headers:
                extracted[h] = r.headers[h]
            else:
                missing.append(h)

        return r, extracted, missing

    except Exception as e:
        print(f"[!] Error: {e}")
        return None, {}, SEC_HEADERS


# 🔹 Pretty Print
def print_header_status(url, headers, missing):
    print(f"\n[+] Checking: {url}")

    if not headers:
        print("[!!!] No security headers present")

    elif len(headers) == len(SEC_HEADERS):
        print("[+] All security headers are present")

    else:
        print("[!] Some security headers are present\n")

        print("[+] Present Headers:")
        for h in headers:
            print(f"    {h}")

        print("\n[-] Missing Headers:")
        for m in missing:
            print(f"    {m}")


# 🔹 Crawl
def crawl(domain, max_pages=10):
    to_visit = [domain]
    all_headers = []

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)

        if url in visited:
            continue

        visited.add(url)

        r, headers, missing = get_headers(url)

        # Always print result
        print_header_status(url, headers, missing)

        # Send to Burp if missing or none
        if not headers or missing:
            proxy_res, _, _ = get_headers(url, use_proxy=True)
           # if proxy_res:
           #     save_evidence(url, proxy_res, "Crawl Finding")

        # Store only meaningful headers for comparison
        if headers:
            all_headers.append(headers)

        # Extract links
        try:
            res = requests.get(url, headers=headers, verify=False, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")

            for tag in soup.find_all(["a", "link", "script"]):
                link = tag.get("href") or tag.get("src")

                if link:
                    full = urljoin(domain, link)

                    if urlparse(full).netloc == urlparse(domain).netloc:
                        if full not in visited:
                            to_visit.append(full)
        except:
            pass

    return all_headers


# 🔹 Compare
def compare(headers_list):
    print("\n[*] Checking header consistency...")

    if len(headers_list) < 2:
        print("[-] Not enough data for comparison")
        return

    base = headers_list[0]

    for i, h in enumerate(headers_list[1:], start=2):
        for key in base:
            if key in h and h[key] != base[key]:
                print(f"[!] Inconsistency in {key}")
                print(f"    Base: {base[key]}")
                print(f"    Page {i}: {h[key]}")


# ---------------- MAIN ----------------

if __name__ == "__main__":

    print("[*] Checking Burp connection...")

    if not is_burp_running():
        print("[!] Burp is NOT running on 127.0.0.1:8080")
        exit()
    else:
        print("[+] Burp is running")

    target = input("\nEnter target URL: ").strip()

    # 🔹 Base endpoint check
    r, headers, missing = get_headers(target)

    print_header_status(target, headers, missing)

    # 🔹 Send to Burp if needed
    if not headers or missing:
        proxy_res, _, _ = get_headers(target, use_proxy=True)
     #   if proxy_res:
     #        save_evidence(target, proxy_res, "Base Finding")

    # 🔹 AI validation only if headers exist
    if headers:
        print("\n[*] AI Validation:")
        print(validate_ai(headers))

    # 🔹 Crawl (independent)
    choice = input("\nCrawl more endpoints? (yes/no): ").lower()

    if choice == "yes":
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        hlist = crawl(base)

        if hlist:
            compare(hlist)