import argparse
from crawler import get_js_files
from downloader import download_all
from detector import detect_all
from retire_db import RetireDB


def banner():
    print("=" * 60)
    print(" LibFinder - JavaScript Library Detection")
    print("=" * 60)


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Discover JavaScript files from a website."
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL"
    )

    args = parser.parse_args()

    print(f"\n[+] Target: {args.url}")

    js_files = get_js_files(args.url)

    print(f"[+] Found {len(js_files)} JavaScript files\n")

    for js in sorted(js_files):
        print(js)

    # ========== Downloading the file=====================

    downloads = download_all(js_files)

    for item in downloads:
        print("=" * 60)
        print("URL :", item["url"])
        print("HTTP:", item["status"])
        print("SIZE:", item["size"])
        print("SHA :", item["sha256"])
        
        if item["banner"]:
            print("Banner Found")
        
        if item["source_map"]:
            print("Source Map:", item["source_map"])
    
    # =============detector=========================

    findings = detect_all(downloads)
    print("\nDetected Libraries\n")
    for f in findings:
        print("-" * 70)
        print("URL        :", f["url"])
        print("Library    :", f["library"])
        print("Version    :", f["version"])
        print("Confidence :", f["confidence"])


    # ======================retire database=======================

    db = RetireDB()
    print(db.stats())


if __name__ == "__main__":
    main()