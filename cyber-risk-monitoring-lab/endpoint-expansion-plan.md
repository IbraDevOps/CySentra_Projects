# Endpoint Expansion Plan

## Objective
Scale Wazuh monitoring from a single lab host to all office endpoints (Windows, macOS, remote laptops).

---

## Deployment Strategy

### Windows Endpoints
- Use silent MSI installer.
- Scripted deployment via PowerShell.
- Centralized configuration with manager hostname.
- Group tagging: finance, admin, operations.

### macOS Endpoints
- Deploy agent via PKG installer.
- Configure manager hostname in agent config.
- Assign to correct logical group.

---

## Remote Systems

For remote users:
- Distribute secure install script.
- Use remote management tools (RMM / SSH).
- Document enrollment key and configuration.

---

## Manager Stability

- Manager configured with static IP.
- Hostname-based configuration preferred.
- Agents auto-reconnect if manager temporarily unreachable.

---

## Agent Grouping Strategy

Groups:
- finance
- operations
- admin
- iot
- test

This enables rule tuning per department.
