import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/138.0 Safari/537.36"
    )
}


def create_session():
    session = requests.Session()

    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )

    adapter = HTTPAdapter(max_retries=retry)

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update(HEADERS)

    return session


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def extract_banner(text):
    """
    Extract the first block comment if present.
    """
    match = re.search(r"/\*![\s\S]{0,4096}?\*/", text)
    if match:
        return match.group(0)

    match = re.search(r"/\*[\s\S]{0,4096}?\*/", text)
    if match:
        return match.group(0)

    return ""


def extract_source_map(text):
    match = re.search(
        r"//# sourceMappingURL=(.+)",
        text
    )

    if match:
        return match.group(1).strip()

    return None


def download_one(url):
    session = create_session()

    result = {
        "url": url,
        "status": None,
        "content": None,
        "text": None,
        "sha256": None,
        "banner": None,
        "source_map": None,
        "size": 0,
        "error": None,
    }

    try:
        response = session.get(url, timeout=20)

        result["status"] = response.status_code

        if response.status_code != 200:
            return result

        content = response.content

        text = response.text

        result["content"] = content
        result["text"] = text
        result["size"] = len(content)
        result["sha256"] = sha256(content)
        result["banner"] = extract_banner(text)
        result["source_map"] = extract_source_map(text)

    except Exception as e:
        result["error"] = str(e)

    return result


def download_all(js_urls, workers=10):
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:

        futures = {
            executor.submit(download_one, url): url
            for url in js_urls
        }

        for future in as_completed(futures):
            results.append(future.result())

    return results