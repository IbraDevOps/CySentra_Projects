import argparse
from datetime import datetime, UTC

from collectors.subdomains import SubdomainCollector
from collectors.dns import DNSCollector
from core.utils import ensure_directory, save_json


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--output-dir", default="reports")
    return parser.parse_args()


def main():
    args = parse_args()

    ensure_directory(args.output_dir)

    # Phase 1
    subdomains = SubdomainCollector(args.domain).collect()

    # Phase 2
    dns_results = DNSCollector(subdomains).collect()

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    output_file = (
        f"{args.output_dir}/dns_scan_{args.domain}_{timestamp}.json"
    )

    resolved_count = sum(1 for x in dns_results if x["resolves"])

    report = {
        "target_domain": args.domain,
        "scan_type": "dns_validation",
        "timestamp_utc": timestamp,
        "generated_candidates": len(subdomains),
        "resolved_assets": resolved_count,
        "results": dns_results,
    }

    save_json(report, output_file)

    print(f"[+] Target: {args.domain}")
    print(f"[+] Candidates: {len(subdomains)}")
    print(f"[+] Resolved: {resolved_count}")
    print(f"[+] Report: {output_file}")

    for item in dns_results:
        if item["resolves"]:
            print(
                f"    [+] {item['subdomain']} -> "
                f"{', '.join(item['ip_addresses'])}"
            )

if __name__ == "__main__":
    main()
