from typing import Any, Dict, List


REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS helps enforce HTTPS connections.",
    "Content-Security-Policy": "CSP helps reduce XSS and content injection risk.",
    "X-Frame-Options": "XFO helps reduce clickjacking risk.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "Referrer-Policy": "Controls referrer information leakage.",
}


def analyze_headers_for_url(url_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze security headers for one HTTP/HTTPS result.
    """
    if not url_result.get("reachable"):
        return {
            "reachable": False,
            "missing_headers": [],
            "present_headers": [],
            "findings": [],
        }

    headers = url_result.get("headers", {}) or {}

    missing_headers = []
    present_headers = []
    findings = []

    for header, description in REQUIRED_SECURITY_HEADERS.items():
        value = headers.get(header)

        if value:
            present_headers.append(header)
        else:
            missing_headers.append(header)
            findings.append(
                {
                    "header": header,
                    "issue": "Missing security header",
                    "description": description,
                }
            )

    return {
        "reachable": True,
        "missing_headers": missing_headers,
        "present_headers": present_headers,
        "findings": findings,
    }


def analyze_web_headers(web_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze headers for all HTTP/HTTPS web results.
    """
    results = []

    for item in web_results:
        subdomain = item["subdomain"]

        results.append(
            {
                "subdomain": subdomain,
                "http": analyze_headers_for_url(item.get("http", {})),
                "https": analyze_headers_for_url(item.get("https", {})),
            }
        )

    return results
