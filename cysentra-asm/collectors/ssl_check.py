import socket
import ssl
from datetime import datetime, UTC
from typing import Any, Dict, List


class SSLCollector:
    def __init__(self, hosts: List[str], timeout: int = 5) -> None:
        self.hosts = hosts
        self.timeout = timeout

    def check_host(self, host: str) -> Dict[str, Any]:
        result = {
            "subdomain": host,
            "ssl_reachable": False,
            "issuer": None,
            "subject": None,
            "not_before": None,
            "not_after": None,
            "days_until_expiry": None,
            "expired": None,
            "expires_soon": None,
            "san": [],
            "error": None,
        }

        try:
            context = ssl.create_default_context()

            with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

            result["ssl_reachable"] = True

            issuer = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))

            result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
            result["subject"] = subject.get("commonName")

            result["not_before"] = cert.get("notBefore")
            result["not_after"] = cert.get("notAfter")

            san = [
                value
                for key, value in cert.get("subjectAltName", [])
                if key.lower() == "dns"
            ]
            result["san"] = san

            if result["not_after"]:
                expiry = datetime.strptime(
                    result["not_after"],
                    "%b %d %H:%M:%S %Y %Z",
                ).replace(tzinfo=UTC)

                now = datetime.now(UTC)
                days_left = (expiry - now).days

                result["days_until_expiry"] = days_left
                result["expired"] = days_left < 0
                result["expires_soon"] = 0 <= days_left <= 30

        except Exception as exc:
            result["error"] = str(exc)

        return result

    def collect(self) -> List[Dict[str, Any]]:
        return [self.check_host(host) for host in self.hosts]
