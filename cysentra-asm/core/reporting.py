from typing import Any, Dict, List


def print_executive_report(findings: List[Dict[str, Any]]) -> None:
    print("\n[+] Executive Risk Report")

    if not findings:
        print("    No findings.")
        return

    shown = False
    for item in findings:
        if item["severity"] == "INFO":
            continue

        shown = True
        print(
            f"    {item['severity']:<7} "
            f"{item['subdomain']:<30} "
            f"Score: {item['score']}"
        )

        for reason in item["reasons"]:
            print(f"        - {reason}")

    if not shown:
        print("    No material risk findings.")
