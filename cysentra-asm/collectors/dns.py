import socket
import ipaddress
from typing import Dict, List


class DNSCollector:
    """
    Resolve subdomains and classify IP addresses.
    """

    def __init__(self, targets: List[str]) -> None:
        self.targets = targets

    def is_public_ip(self, ip: str) -> bool:
        """
        Return True if IP is public routable.
        """
        try:
            parsed = ipaddress.ip_address(ip)
            return not (
                parsed.is_private
                or parsed.is_loopback
                or parsed.is_reserved
                or parsed.is_multicast
                or parsed.is_link_local
            )
        except ValueError:
            return False

    def resolve_host(self, host: str) -> Dict:
        """
        Resolve host to IPv4 addresses.
        """
        result = {
            "subdomain": host,
            "resolves": False,
            "ip_addresses": [],
            "public_ip": False,
        }

        try:
            _, _, ips = socket.gethostbyname_ex(host)

            unique_ips = sorted(list(set(ips)))

            result["resolves"] = True
            result["ip_addresses"] = unique_ips
            result["public_ip"] = any(
                self.is_public_ip(ip) for ip in unique_ips
            )

        except socket.gaierror:
            pass

        return result

    def collect(self) -> List[Dict]:
        """
        Resolve all targets.
        """
        findings = []

        for host in self.targets:
            findings.append(self.resolve_host(host))

        return findings
