import argparse
from datetime import UTC, datetime
from typing import Any, Dict, List

from collectors.dns import DNSCollector
from collectors.ssl_check import SSLCollector
from collectors.subdomains import SubdomainCollector
from collectors.web import WebCollector
from core.db import DatabaseManager
from core.diff import diff_assets
from core.exporters import export_csv_findings, export_html_report
from core.header_analysis import analyze_web_headers
from core.reporting import print_executive_report
from core.scoring import score_all_assets
from core.utils import ensure_directory, save_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CySentra ASM - External Attack Surface Monitoring"
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("--output-dir", default="reports")
    return parser.parse_args()


def merge_asset_data(
    dns_results: List[Dict[str, Any]],
    web_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    web_index = {item["subdomain"]: item for item in web_results}
    merged = []

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
    return {
        "new_hosts": [
            asset["subdomain"]
            for asset in current_assets
            if asset.get("resolves")
        ],
        "removed_hosts": [],
        "changed_hosts": [],
    }


def print_source_stats(source_stats: Dict[str, int]) -> None:
    print("\n[+] Subdomain Source Stats:")
    for source, count in source_stats.items():
        print(f"    - {source}: {count}")


def print_monitoring_summary(
    domain: str,
    scan_id: int,
    previous_scan_id: int | None,
    subdomains: List[str],
    resolved_hosts: List[str],
    web_results: List[Dict[str, Any]],
    diff_results: Dict[str, Any],
    output_file: str,
    csv_file: str,
    html_file: str,
) -> None:
    print(f"[+] Target: {domain}")
    print(f"[+] Scan ID: {scan_id}")
    print(f"[+] Previous Scan ID: {previous_scan_id}")
    print(f"[+] Candidates: {len(subdomains)}")
    print(f"[+] Resolved: {len(resolved_hosts)}")
    print(f"[+] Fingerprinted: {len(web_results)}")
    print(f"[+] New Hosts: {len(diff_results['new_hosts'])}")
    print(f"[+] Removed Hosts: {len(diff_results['removed_hosts'])}")
    print(f"[+] Changed Hosts: {len(diff_results['changed_hosts'])}")
    print(f"[+] JSON Report: {output_file}")
    print(f"[+] CSV Report: {csv_file}")
    print(f"[+] HTML Report: {html_file}")


def print_recon_summary(
    subdomains: List[str],
    dns_results: List[Dict[str, Any]],
    web_results: List[Dict[str, Any]],
    diff_results: Dict[str, Any],
) -> None:
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


def print_header_analysis(header_results: List[Dict[str, Any]]) -> None:
    print("\n[+] Security Header Analysis")

    any_findings = False

    for item in header_results:
        subdomain = item["subdomain"]

        for scheme in ("http", "https"):
            result = item.get(scheme, {})

            if not result.get("reachable"):
                continue

            missing = result.get("missing_headers", [])

            if missing:
                any_findings = True
                print(f"    - {subdomain} [{scheme.upper()}]")
                for header in missing:
                    print(f"        Missing: {header}")

    if not any_findings:
        print("    No missing security headers detected on reachable assets.")


def print_ssl_summary(ssl_results: List[Dict[str, Any]]) -> None:
    print("\n[+] SSL/TLS Certificate Analysis")

    for item in ssl_results:
        host = item["subdomain"]

        if not item.get("ssl_reachable"):
            print(f"    - {host}: SSL unreachable")
            continue

        print(f"    - {host}")
        print(f"        Issuer: {item.get('issuer')}")
        print(f"        Subject: {item.get('subject')}")
        print(f"        Valid From: {item.get('not_before')}")
        print(f"        Valid Until: {item.get('not_after')}")
        print(f"        Days Until Expiry: {item.get('days_until_expiry')}")

        if item.get("expired"):
            print("        Warning: certificate is expired")

        if item.get("expires_soon"):
            print("        Warning: certificate expires soon")

        san = item.get("san") or []
        if san:
            print(f"        SANs: {', '.join(san[:5])}")


def main() -> None:
    args = parse_args()
    ensure_directory(args.output_dir)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    # Phase 6: enhanced subdomain discovery with source statistics
    subdomain_collector = SubdomainCollector(args.domain)
    subdomain_result = subdomain_collector.collect_with_sources()
    subdomains = subdomain_result["subdomains"]
    source_stats = subdomain_result["source_stats"]

    # Phase 2: DNS validation
    dns_results = DNSCollector(subdomains).collect()
    resolved_hosts = [item["subdomain"] for item in dns_results if item["resolves"]]

    # Phase 3: Web fingerprinting
    web_results = WebCollector(resolved_hosts).collect()

    # Phase 7: Security header analysis
    header_results = analyze_web_headers(web_results)

    # Phase 8: SSL/TLS certificate intelligence
    ssl_results = SSLCollector(resolved_hosts).collect()

    # Phase 4: Storage + diff
    merged_assets = merge_asset_data(dns_results, web_results)

    db = DatabaseManager()
    try:
        scan_id = db.insert_scan(args.domain, "phase9_reporting_exports", timestamp)

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

        # Phase 5: Risk scoring
        findings = score_all_assets(current_assets, diff_results["new_hosts"])

        output_file = f"{args.output_dir}/phase9_scan_{args.domain}_{timestamp}.json"

        report = {
            "target_domain": args.domain,
            "scan_type": "phase9_reporting_exports",
            "timestamp_utc": timestamp,
            "scan_id": scan_id,
            "previous_scan_id": previous_scan_id,
            "subdomain_source_stats": source_stats,
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
            "header_analysis": header_results,
            "ssl_results": ssl_results,
            "dns_results": dns_results,
            "web_results": web_results,
        }

        save_json(report, output_file)

        csv_file = export_csv_findings(findings, output_file)
        html_file = export_html_report(
            args.domain,
            findings,
            output_file,
            len(resolved_hosts),
        )

        print_monitoring_summary(
            domain=args.domain,
            scan_id=scan_id,
            previous_scan_id=previous_scan_id,
            subdomains=subdomains,
            resolved_hosts=resolved_hosts,
            web_results=web_results,
            diff_results=diff_results,
            output_file=output_file,
            csv_file=csv_file,
            html_file=html_file,
        )

        print_source_stats(source_stats)

        print_recon_summary(
            subdomains=subdomains,
            dns_results=dns_results,
            web_results=web_results,
            diff_results=diff_results,
        )

        print_header_analysis(header_results)
        print_ssl_summary(ssl_results)
        print_executive_report(findings)

    finally:
        db.close()


if __name__ == "__main__":
    main()
