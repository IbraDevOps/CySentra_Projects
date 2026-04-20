from pathlib import Path
from typing import List, Set

from core.utils import normalize_subdomain, is_valid_subdomain


DEFAULT_SUBDOMAIN_WORDLIST = [
    "www",
    "api",
    "dev",
    "test",
    "staging",
    "portal",
    "admin",
    "mail",
    "blog",
    "vpn",
    "app",
    "m",
    "secure",
    "auth",
    "dashboard",
]


class SubdomainCollector:
    """
    Collects candidate subdomains for a target domain.
    Phase 1 uses a simple wordlist-based approach.
    """

    def __init__(self, target_domain: str, wordlist: List[str] | None = None) -> None:
        self.target_domain = normalize_subdomain(target_domain)
        self.wordlist = wordlist or DEFAULT_SUBDOMAIN_WORDLIST

    def generate_candidates(self) -> Set[str]:
        """
        Generate candidate subdomains from the configured wordlist.
        """
        candidates = set()

        for word in self.wordlist:
            word = word.strip().lower()
            if not word:
                continue

            candidate = f"{word}.{self.target_domain}"
            candidate = normalize_subdomain(candidate)

            if is_valid_subdomain(candidate, self.target_domain):
                candidates.add(candidate)

        return candidates

    def load_wordlist_from_file(self, file_path: str) -> List[str]:
        """
        Load additional subdomain prefixes from a file.
        One entry per line.
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Wordlist file not found: {file_path}")

        words = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                item = line.strip().lower()
                if item:
                    words.append(item)

        return words

    def collect(self) -> List[str]:
        """
        Return a sorted list of unique candidate subdomains.
        """
        candidates = self.generate_candidates()
        return sorted(candidates)
