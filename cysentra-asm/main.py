import argparse
from datetime import datetime

from collectors.subdomains import SubdomainCollector
from core.utils import ensure_directory, save_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CySentra ASM - External Attack Surface Monitoring"
    )
    parser.add_argument(
        "domain",
        help="Target domain to monitor (e.g. example.com)",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory where JSON output will be saved",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    ensure_directory(args.output_dir)

    collector = SubdomainCollector(args.domain)
    subdomains = collector.collect()

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_file = f"{args.output_dir}/subdomains_{args.domain}_{timestamp}.json"

    results = {
        "target_domain": args.domain,
        "scan_type": "subdomain_discovery",
        "timestamp_utc": timestamp,
        "count": len(subdomains),
        "subdomains": subdomains,
    }

    save_json(results, output_file)

    print(f"[+] Target domain: {args.domain}")
    print(f"[+] Subdomains generated: {len(subdomains)}")
    print(f"[+] Results saved to: {output_file}")

    for subdomain in subdomains:
        print(f"    - {subdomain}")


if __name__ == "__main__":
    main()
