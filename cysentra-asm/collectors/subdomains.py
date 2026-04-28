import json
import shutil
import subprocess
from typing import Dict, List, Set

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
        self.source_stats: Dict[str, int] = {
            "wordlist": 0,
            "crtsh": 0,
            "amass": 0,
            "total_unique": 0,
        }

    def generate_wordlist_candidates(self) -> Set[str]:
        results = set()

        for word in self.wordlist:
            word = word.strip().lower()
            if not word:
                continue

            candidate = normalize_subdomain(f"{word}.{self.target_domain}")

            if is_valid_subdomain(candidate, self.target_domain):
                results.add(candidate)

        self.source_stats["wordlist"] = len(results)
        return results

    def collect_from_crtsh(self) -> Set[str]:
        """
        Collect subdomains from crt.sh certificate transparency logs.
        Some domains may return 404 if no records are available.
        """
        results = set()
        url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"

        headers = {
            "User-Agent": "CySentra-ASM/0.1"
        }

        try:
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 404:
                print("[!] crt.sh returned no records.")
                self.source_stats["crtsh"] = 0
                return results

            response.raise_for_status()

            try:
                entries = response.json()
            except json.JSONDecodeError:
                print("[!] crt.sh returned invalid JSON.")
                self.source_stats["crtsh"] = 0
                return results

            for entry in entries:
                name_value = entry.get("name_value", "")

                for name in name_value.split("\n"):
                    cleaned = normalize_subdomain(name.replace("*.", ""))

                    if is_valid_subdomain(cleaned, self.target_domain):
                        results.add(cleaned)

        except requests.RequestException as exc:
            print(f"[!] crt.sh lookup failed: {exc}")

        self.source_stats["crtsh"] = len(results)
        return results

    def collect_from_amass(self) -> Set[str]:
        """
        Collect subdomains using Amass passive mode.
        Requires amass to be installed.
        """
        results = set()

        if not shutil.which("amass"):
            print("[!] Amass not found. Skipping Amass passive enumeration.")
            self.source_stats["amass"] = 0
            return results

        command = [
            "amass",
            "enum",
            "-passive",
            "-d",
            self.target_domain,
            "-timeout",
            "3",
        ]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=240,
                check=False,
            )

            for line in completed.stdout.splitlines():
                cleaned = normalize_subdomain(line.strip())

                if is_valid_subdomain(cleaned, self.target_domain):
                    results.add(cleaned)

            if completed.stderr.strip():
                print(f"[!] Amass warning: {completed.stderr.strip()}")

        except subprocess.TimeoutExpired:
            print("[!] Amass passive enumeration timed out.")

        self.source_stats["amass"] = len(results)
        return results

    def collect_with_sources(self) -> Dict[str, List[str] | Dict[str, int]]:
        """
        Collect subdomains and return both results and source statistics.
        """
        wordlist_results = self.generate_wordlist_candidates()
        crtsh_results = self.collect_from_crtsh()
        amass_results = self.collect_from_amass()

        all_results = set()
        all_results.update(wordlist_results)
        all_results.update(crtsh_results)
        all_results.update(amass_results)

        self.source_stats["total_unique"] = len(all_results)

        return {
            "subdomains": sorted(all_results),
            "source_stats": self.source_stats,
        }

    def collect(self) -> List[str]:
        """
        Backward-compatible method used by main.py.
        """
        result = self.collect_with_sources()
        return result["subdomains"]  # type: ignore[return-value]
