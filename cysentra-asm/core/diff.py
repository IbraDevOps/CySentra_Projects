from typing import Any, Dict, List


def _index_assets(assets: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {asset["subdomain"]: asset for asset in assets}


def diff_assets(previous_assets: List[Dict[str, Any]], current_assets: List[Dict[str, Any]]) -> Dict[str, Any]:
    previous_index = _index_assets(previous_assets)
    current_index = _index_assets(current_assets)

    previous_hosts = set(previous_index.keys())
    current_hosts = set(current_index.keys())

    new_hosts = sorted(list(current_hosts - previous_hosts))
    removed_hosts = sorted(list(previous_hosts - current_hosts))

    changed_hosts = []

    shared_hosts = previous_hosts & current_hosts

    tracked_fields = [
        "resolves",
        "ip_addresses",
        "http_status",
        "https_status",
        "http_title",
        "https_title",
        "http_server",
        "https_server",
    ]

    for host in sorted(shared_hosts):
        prev = previous_index[host]
        curr = current_index[host]

        changes = {}
        for field in tracked_fields:
            if prev.get(field) != curr.get(field):
                changes[field] = {
                    "previous": prev.get(field),
                    "current": curr.get(field),
                }

        if changes:
            changed_hosts.append({
                "subdomain": host,
                "changes": changes,
            })

    return {
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
        "changed_hosts": changed_hosts,
    }
