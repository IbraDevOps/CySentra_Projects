from typing import Dict, List, Optional

import requests
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 5

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


class WebCollector:
    """
    Fingerprint HTTP/HTTPS services for resolved hosts.
    """

    def __init__(self, hosts: List[str], timeout: int = DEFAULT_TIMEOUT) -> None:
        self.hosts = hosts
        self.timeout = timeout

    def extract_title(self, html: str) -> Optional[str]:
        """
        Extract HTML title if present.
        """
        try:
            soup = BeautifulSoup(html, "html.parser")
            if soup.title and soup.title.string:
                return soup.title.string.strip()
        except Exception:
            return None
        return None

    def header_subset(self, headers: requests.structures.CaseInsensitiveDict) -> Dict[str, Optional[str]]:
        """
        Return selected security headers and common server header.
        """
        result: Dict[str, Optional[str]] = {
            "Server": headers.get("Server")
        }

        for header in SECURITY_HEADERS:
            result[header] = headers.get(header)

        return result

    def fetch_url(self, url: str) -> Dict:
        """
        Request a URL and return structured fingerprinting data.
        """
        result = {
            "url": url,
            "reachable": False,
            "status_code": None,
            "final_url": None,
            "title": None,
            "headers": {},
            "error": None,
        }

        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "CySentra-ASM/0.1"},
            )

            result["reachable"] = True
            result["status_code"] = response.status_code
            result["final_url"] = response.url
            result["title"] = self.extract_title(response.text)
            result["headers"] = self.header_subset(response.headers)

        except requests.RequestException as exc:
            result["error"] = str(exc)

        return result

    def fingerprint_host(self, host: str) -> Dict:
        """
        Check both HTTP and HTTPS for a host.
        """
        http_result = self.fetch_url(f"http://{host}")
        https_result = self.fetch_url(f"https://{host}")

        return {
            "subdomain": host,
            "http": http_result,
            "https": https_result,
        }

    def collect(self) -> List[Dict]:
        """
        Fingerprint all provided hosts.
        """
        return [self.fingerprint_host(host) for host in self.hosts]
