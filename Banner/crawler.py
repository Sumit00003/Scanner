import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from urllib.parse import urlparse
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
        allowed_methods=["GET", "HEAD"]
    )

    adapter = HTTPAdapter(max_retries=retry)

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update(HEADERS)

    return session


def normalize(url):
    parsed = urlparse(url)

    if not parsed.scheme:
        return "https://" + url

    return url


def get_html(session, url):
    response = session.get(
        url,
        timeout=20,
        allow_redirects=True
    )

    response.raise_for_status()

    return response.text


def extract_scripts(base_url, html):
    soup = BeautifulSoup(html, "html.parser")

    js_files = set()

    for script in soup.find_all("script"):
        src = script.get("src")

        if not src:
            continue

        absolute = urljoin(base_url, src)

        js_files.add(absolute)

    return js_files


def get_js_files(url):
    url = normalize(url)

    session = create_session()

    try:
        html = get_html(session, url)
    except Exception as e:
        print(f"[-] Failed to fetch page: {e}")
        return set()

    return extract_scripts(url, html)