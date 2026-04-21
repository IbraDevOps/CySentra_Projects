import argparse
from datetime import UTC, datetime

from collectors.dns import DNSCollector
from collectors.subdomains import SubdomainCollector
from collectors.web import WebCollector
from core.db import DatabaseManager
from core.diff import diff_assets
from core.utils import ensure_directory, save_json


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--output-dir", default="reports")
    return parser.parse_args()


def merge_asset_data(dns_results, web_results):
    web_index = {item["subdomain"]: item for item in web_results}
    merged = []

    for dns_item in dns_results:
        host = dns_item["subdomain"]
        web_item = web_index.get(host, {})

        http_data = web_item.get("http", {})
        https_data = web_item.get("https", {})

        merged.append({
            "subdomain": host,
            "resolves": dns_item["resolves"],
            "ip_addresses": dns_item.get("ip_addresses", []),
            "http_status": http_data.get("status_code"),
            "https_status": https_data.get("status_code"),
            "http_title": http_data.get("title"),
            "https_title": https_data.get("title"),
            "http_server": http_data.get("headers", {}).get("Server"),
            "https_server": https_data.get("headers", {}).get("Server"),
        })

    return merged


def main():
    args = parse_args()
    ensure_directory(args.output_dir)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    subdomains = SubdomainCollector(args.domain).collect()
    dns_results = DNSCollector(subdomains).collect()
    resolved_hosts = [item["subdomain"] for item in dns_results if item["resolves"]]
    web_results = WebCollector(resolved_hosts).collect()

    merged_assets = merge_asset_data(dns_results, web_results)

    db = DatabaseManager()
    scan_id = db.insert_scan(args.domain, "web_fingerprinting", timestamp)

    for asset in merged_assets:
        db.insert_asset(scan_id, asset)

    previous_scan_id = db.get_previous_scan_id(args.domain, scan_id)
    previous_assets = db.get_assets_by_scan_id(previous_scan_id) if previous_scan_id else []
    current_assets = db.get_assets_by_scan_id(scan_id)

    diff_results = diff_assets(previous_assets, current_assets) if previous_scan_id else {
        "new_hosts": [asset["subdomain"] for asset in current_assets],
        "removed_hosts": [],
        "changed_hosts": [],
    }

    output_file = f"{args.output_dir}/phase4_scan_{args.domain}_{timestamp}.json"

    report = {
        "target_domain": args.domain,
        "scan_type": "storage_and_diff",
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
        "dns_results": dns_results,
        "web_results": web_results,
    }

    save_json(report, output_file)

    print(f"[+] Target: {args.domain}")
    print(f"[+] Scan ID: {scan_id}")
    print(f"[+] Previous Scan ID: {previous_scan_id}")
    print(f"[+] Candidates: {len(subdomains)}")
    print(f"[+] Resolved: {len(resolved_hosts)}")
    print(f"[+] Fingerprinted: {len(web_results)}")
    print(f"[+] New Hosts: {len(diff_results['new_hosts'])}")
    print(f"[+] Removed Hosts: {len(diff_results['removed_hosts'])}")
    print(f"[+] Changed Hosts: {len(diff_results['changed_hosts'])}")
    print(f"[+] Report: {output_file}")

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

    db.close()


if __name__ == "__main__":
    main()
