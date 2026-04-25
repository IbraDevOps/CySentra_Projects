import json
import subprocess
from typing import List, Set

import requests

from core.utils import is_valid_subdomain, normalize_subdomain


DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "api", "dev", "test", "staging", "portal", "admin",
    "mail", "blog", "vpn", "app", "m", "secure", "auth", "dashboard",
]


class SubdomainCollector:
    """
    Collect subdomains from multiple passive sources:
    - built-in wordlist
    - crt.sh certificate transparency logs
    - amass passive mode
    """

    def __init__(self, target_domain: str, wordlist: List[str] | None = None) -> None:
        self.target_domain = normalize_subdomain(target_domain)
        self.wordlist = wordlist or DEFAULT_SUBDOMAIN_WORDLIST

    def generate_wordlist_candidates(self) -> Set[str]:
        candidates = set()

        for word in self.wordlist:
            word = word.strip().lower()
            if not word:
                continue

            candidate = normalize_subdomain(f"{word}.{self.target_domain}")

            if is_valid_subdomain(candidate, self.target_domain):
                candidates.add(candidate)

        return candidates

    def collect_from_crtsh(self) -> Set[str]:
        """
        Collect subdomains from crt.sh certificate transparency data.
        """
        results = set()
        url = f"https://crt.sh/?q=%25.{self.target_domain}&output=json"

        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()

            entries = json.loads(response.text)

            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    cleaned = normalize_subdomain(name.replace("*.", ""))
                    if is_valid_subdomain(cleaned, self.target_domain):
                        results.add(cleaned)

        except Exception as exc:
            print(f"[!] crt.sh lookup failed: {exc}")

        return results

    def collect_from_amass(self) -> Set[str]:
        """
        Collect subdomains using Amass passive mode.
        Requires amass to be installed.
        """
        results = set()

        command = [
            "amass",
            "enum",
            "-passive",
            "-d",
            self.target_domain,
        ]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )

            for line in completed.stdout.splitlines():
                cleaned = normalize_subdomain(line)
                if is_valid_subdomain(cleaned, self.target_domain):
                    results.add(cleaned)

            if completed.stderr.strip():
                print(f"[!] Amass warning: {completed.stderr.strip()}")

        except FileNotFoundError:
            print("[!] Amass not found. Skipping Amass passive enumeration.")
        except subprocess.TimeoutExpired:
            print("[!] Amass passive enumeration timed out.")

        return results

    def collect(self) -> List[str]:
        """
        Collect, merge, deduplicate, and sort discovered subdomains.
        """
        all_results = set()

        wordlist_results = self.generate_wordlist_candidates()
        crtsh_results = self.collect_from_crtsh()
        amass_results = self.collect_from_amass()

        all_results.update(wordlist_results)
        all_results.update(crtsh_results)
        all_results.update(amass_results)

        return sorted(all_results)
