import json
import re
from pathlib import Path
from typing import Any


def ensure_directory(path: str) -> None:
    """Create directory if it does not exist."""
    Path(path).mkdir(parents=True, exist_ok=True)


def save_json(data: Any, output_path: str) -> None:
    """Save data to a JSON file."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def normalize_subdomain(name: str) -> str:
    """
    Normalize subdomain names by:
    - stripping whitespace
    - converting to lowercase
    - removing protocol prefixes
    - removing trailing dots/slashes
    """
    cleaned = name.strip().lower()
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.rstrip("./")
    return cleaned


def is_valid_subdomain(candidate: str, target_domain: str) -> bool:
    """
    Check whether a candidate looks like a valid subdomain of the target domain.
    """
    candidate = normalize_subdomain(candidate)
    target_domain = normalize_subdomain(target_domain)

    if not candidate or " " in candidate:
        return False

    if candidate == target_domain:
        return False

    return candidate.endswith(f".{target_domain}")
