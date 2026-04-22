from typing import Any, Dict, List


def score_asset(asset: Dict[str, Any], new_hosts: List[str]) -> Dict[str, Any]:
    score = 0
    reasons = []

    host = asset["subdomain"]

    title = (asset.get("http_title") or "") + " " + (asset.get("https_title") or "")
    title = title.lower()

    if host in new_hosts:
        score += 20
        reasons.append("Newly discovered host")

    if "login" in title:
        score += 35
        reasons.append("Login portal exposed")

    if "admin" in title or "dashboard" in title:
        score += 25
        reasons.append("Admin/dashboard page detected")

    if asset.get("http_status") and not asset.get("https_status"):
        score += 20
        reasons.append("HTTP reachable without HTTPS")

    if asset.get("resolves") and not asset.get("http_status") and not asset.get("https_status"):
        score += 10
        reasons.append("Resolves but no web response")

    if score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    elif score > 0:
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        "subdomain": host,
        "score": score,
        "severity": severity,
        "reasons": reasons,
    }


def score_all_assets(assets: List[Dict[str, Any]], new_hosts: List[str]) -> List[Dict[str, Any]]:
    findings = [score_asset(asset, new_hosts) for asset in assets]
    findings.sort(key=lambda x: x["score"], reverse=True)
    return findings
