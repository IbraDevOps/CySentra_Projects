import argparse
from datetime import UTC, datetime

from collectors.dns import DNSCollector
from collectors.subdomains import SubdomainCollector
from collectors.web import WebCollector
from core.utils import ensure_directory, save_json


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--output-dir", default="reports")
    return parser.parse_args()


def main():
    args = parse_args()

    ensure_directory(args.output_dir)

    # Phase 1: Candidate generation
    subdomains = SubdomainCollector(args.domain).collect()

    # Phase 2: DNS validation
    dns_results = DNSCollector(subdomains).collect()
    resolved_hosts = [item["subdomain"] for item in dns_results if item["resolves"]]

    # Phase 3: Web fingerprinting
    web_results = WebCollector(resolved_hosts).collect()

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    output_file = f"{args.output_dir}/web_scan_{args.domain}_{timestamp}.json"

    report = {
        "target_domain": args.domain,
        "scan_type": "web_fingerprinting",
        "timestamp_utc": timestamp,
        "generated_candidates": len(subdomains),
        "resolved_assets": len(resolved_hosts),
        "fingerprinted_assets": len(web_results),
        "dns_results": dns_results,
        "web_results": web_results,
    }

    save_json(report, output_file)

    print(f"[+] Target: {args.domain}")
    print(f"[+] Candidates: {len(subdomains)}")
    print(f"[+] Resolved: {len(resolved_hosts)}")
    print(f"[+] Fingerprinted: {len(web_results)}")
    print(f"[+] Report: {output_file}")

    for item in web_results:
        print(f"\n[+] Host: {item['subdomain']}")

        for scheme in ("http", "https"):
            result = item[scheme]
            if result["reachable"]:
                print(
                    f"    [{scheme.upper()}] {result['status_code']} "
                    f"-> {result['final_url']}"
                )
                if result["title"]:
                    print(f"        Title: {result['title']}")
                server = result["headers"].get("Server")
                if server:
                    print(f"        Server: {server}")
            else:
                print(f"    [{scheme.upper()}] Unreachable")

if __name__ == "__main__":
    main()
