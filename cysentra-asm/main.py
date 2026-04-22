import argparse
from datetime import UTC, datetime
from typing import Any, Dict, List

from collectors.dns import DNSCollector
from collectors.subdomains import SubdomainCollector
from collectors.web import WebCollector
from core.db import DatabaseManager
from core.diff import diff_assets
from core.reporting import print_executive_report
from core.scoring import score_all_assets
from core.utils import ensure_directory, save_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CySentra ASM - External Attack Surface Monitoring"
    )
    parser.add_argument(
        "domain",
        help="Target domain (e.g. example.com)",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory where JSON reports will be saved",
    )
    return parser.parse_args()


def merge_asset_data(
    dns_results: List[Dict[str, Any]],
    web_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Merge DNS validation results with web fingerprinting results into
    a single asset-centric structure.
    """
    web_index = {item["subdomain"]: item for item in web_results}
    merged: List[Dict[str, Any]] = []

    for dns_item in dns_results:
        host = dns_item["subdomain"]
        web_item = web_index.get(host, {})

        http_data = web_item.get("http", {})
        https_data = web_item.get("https", {})

        merged.append(
            {
                "subdomain": host,
                "resolves": dns_item["resolves"],
                "ip_addresses": dns_item.get("ip_addresses", []),
                "public_ip": dns_item.get("public_ip", False),
                "http_status": http_data.get("status_code"),
                "https_status": https_data.get("status_code"),
                "http_title": http_data.get("title"),
                "https_title": https_data.get("title"),
                "http_server": http_data.get("headers", {}).get("Server"),
                "https_server": https_data.get("headers", {}).get("Server"),
            }
        )

    return merged


def build_initial_diff(current_assets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    For a first baseline scan, only resolved assets are counted as new hosts.
    """
    new_hosts = [
        asset["subdomain"]
        for asset in current_assets
        if asset.get("resolves")
    ]

    return {
        "new_hosts": new_hosts,
        "removed_hosts": [],
        "changed_hosts": [],
    }


def print_monitoring_summary(
    domain: str,
    scan_id: int,
    previous_scan_id: int | None,
    subdomains: List[str],
    resolved_hosts: List[str],
    web_results: List[Dict[str, Any]],
    diff_results: Dict[str, Any],
    output_file: str,
) -> None:
    """
    Print monitoring-oriented summary information.
    """
    print(f"[+] Target: {domain}")
    print(f"[+] Scan ID: {scan_id}")
    print(f"[+] Previous Scan ID: {previous_scan_id}")
    print(f"[+] Candidates: {len(subdomains)}")
    print(f"[+] Resolved: {len(resolved_hosts)}")
    print(f"[+] Fingerprinted: {len(web_results)}")
    print(f"[+] New Hosts: {len(diff_results['new_hosts'])}")
    print(f"[+] Removed Hosts: {len(diff_results['removed_hosts'])}")
    print(f"[+] Changed Hosts: {len(diff_results['changed_hosts'])}")
    print(f"[+] Report: {output_file}")


def print_recon_summary(
    subdomains: List[str],
    dns_results: List[Dict[str, Any]],
    web_results: List[Dict[str, Any]],
    diff_results: Dict[str, Any],
) -> None:
    """
    Print recon-style details to the terminal.
    """
    if subdomains:
        print("\n[+] Candidate Subdomains:")
        for subdomain in subdomains:
            print(f"    - {subdomain}")

    resolved_assets = [item for item in dns_results if item["resolves"]]
    if resolved_assets:
        print("\n[+] Resolved Assets:")
        for item in resolved_assets:
            ips = ", ".join(item["ip_addresses"]) if item["ip_addresses"] else "N/A"
            public_flag = "public" if item.get("public_ip") else "non-public"
            print(f"    - {item['subdomain']} -> {ips} ({public_flag})")

    if web_results:
        print("\n[+] Web Fingerprinting:")
        for item in web_results:
            print(f"    - Host: {item['subdomain']}")

            for scheme in ("http", "https"):
                result = item.get(scheme, {})

                if result.get("reachable"):
                    print(
                        f"        [{scheme.upper()}] {result.get('status_code')} "
                        f"-> {result.get('final_url')}"
                    )

                    if result.get("title"):
                        print(f"            Title: {result['title']}")

                    server = result.get("headers", {}).get("Server")
                    if server:
                        print(f"            Server: {server}")
                else:
                    print(f"        [{scheme.upper()}] Unreachable")

    if diff_results["new_hosts"]:
        print("\n[+] New Hosts:")
        for host in diff_results["new_hosts"]:
            print(f"    - {host}")

    if diff_results["removed_hosts"]:
        print("\n[+] Removed Hosts:")
        for host in diff_results["removed_hosts"]:
            print(f"    - {host}")

    if diff_results["changed_hosts"]:
        print("\n[+] Changed Hosts:")
        for item in diff_results["changed_hosts"]:
            print(f"    - {item['subdomain']}")
            for field, values in item["changes"].items():
                print(f"        {field}: {values['previous']} -> {values['current']}")


def main() -> None:
    args = parse_args()
    ensure_directory(args.output_dir)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    # Phase 1: candidate subdomain generation
    subdomains = SubdomainCollector(args.domain).collect()

    # Phase 2: DNS resolution / validation
    dns_results = DNSCollector(subdomains).collect()
    resolved_hosts = [item["subdomain"] for item in dns_results if item["resolves"]]

    # Phase 3: HTTP/HTTPS fingerprinting
    web_results = WebCollector(resolved_hosts).collect()

    # Merge DNS + web into one asset view
    merged_assets = merge_asset_data(dns_results, web_results)

    db = DatabaseManager()
    try:
        # Phase 4: store current scan
        scan_id = db.insert_scan(args.domain, "storage_and_diff", timestamp)

        for asset in merged_assets:
            db.insert_asset(scan_id, asset)

        previous_scan_id = db.get_previous_scan_id(args.domain, scan_id)
        previous_assets = (
            db.get_assets_by_scan_id(previous_scan_id) if previous_scan_id else []
        )
        current_assets = db.get_assets_by_scan_id(scan_id)

        if previous_scan_id:
            diff_results = diff_assets(previous_assets, current_assets)
        else:
            diff_results = build_initial_diff(current_assets)

        # Phase 5: risk scoring
        findings = score_all_assets(current_assets, diff_results["new_hosts"])

        output_file = f"{args.output_dir}/phase5_scan_{args.domain}_{timestamp}.json"

        report = {
            "target_domain": args.domain,
            "scan_type": "risk_scored_monitoring",
            "timestamp_utc": timestamp,
            "scan_id": scan_id,
            "previous_scan_id": previous_scan_id,
            "generated_candidates": len(subdomains),
            "resolved_assets": len(resolved_hosts),
            "fingerprinted_assets": len(web_results),
            "diff_summary": {
                "new_hosts": len(diff_results["new_hosts"]),
                "removed_hosts": len(diff_results["removed_hosts"]),
                "changed_hosts": len(diff_results["changed_hosts"]),
            },
            "diff_results": diff_results,
            "risk_findings": findings,
            "dns_results": dns_results,
            "web_results": web_results,
        }

        save_json(report, output_file)

        print_monitoring_summary(
            domain=args.domain,
            scan_id=scan_id,
            previous_scan_id=previous_scan_id,
            subdomains=subdomains,
            resolved_hosts=resolved_hosts,
            web_results=web_results,
            diff_results=diff_results,
            output_file=output_file,
        )

        print_recon_summary(
            subdomains=subdomains,
            dns_results=dns_results,
            web_results=web_results,
            diff_results=diff_results,
        )

        print_executive_report(findings)

    finally:
        db.close()


if __name__ == "__main__":
    main()
