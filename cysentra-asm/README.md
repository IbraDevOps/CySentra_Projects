# CySentra ASM (Attack Surface Monitor)

## Overview

CySentra ASM is a Python-based External Attack Surface Monitoring platform designed to help organizations understand and monitor what they expose to the internet. It discovers public-facing assets, fingerprints services, tracks changes over time, and produces risk-oriented reports.

This project is built as:

* A practical cybersecurity engineering portfolio project
* A foundation for a client-facing security monitoring service
* A learning journey in Python automation, reconnaissance, and reporting
* A reusable platform for SMEs seeking visibility into external exposure

## Problem Statement

Many organizations do not have a clear inventory of their internet-facing assets. New subdomains, expired certificates, exposed login portals, forgotten staging systems, and risky configuration changes often go unnoticed.

Attackers look for these gaps first.

CySentra ASM helps defenders continuously answer:

* What public assets do we expose?
* What changed since the last scan?
* Which findings appear risky?
* What should be reviewed first?

## Core Workflow

```text
Target Domain
   ↓
Asset Discovery
   ↓
Validation (DNS / Reachability)
   ↓
Web Fingerprinting
   ↓
SSL/TLS Inspection
   ↓
Snapshot Storage
   ↓
Change Detection
   ↓
Risk Scoring
   ↓
Reporting
```

## Version 1 Scope

The first release focuses on five core capabilities:

1. Subdomain discovery
2. DNS resolution and live host checks
3. HTTP/HTTPS fingerprinting (status, title, headers)
4. SSL certificate inspection
5. Change tracking between scans

## Example Findings

* New subdomain discovered
* Public login portal exposed
* SSL certificate expires in 10 days
* Missing security headers
* Previously offline asset is reachable again
* Page title changed unexpectedly

## Why This Matters

This project moves beyond one-time scanning. It introduces historical visibility and change detection, which creates real operational value for security teams and SMEs.

## Use Cases

* External attack surface monitoring for SMEs
* Monthly security visibility reports
* Pre-audit visibility for ISO 27001 / PCI-DSS readiness
* Security consulting demonstrations


##Planned Tech Stack

* Python 3
* SQLite
* requests / httpx
* dnspython
* ssl / socket
* JSON / CSV reporting
* Optional: subfinder, httpx CLI tools

## Project Structure

```text
cysentra-asm/
├── README.md
├── requirements.txt
├── main.py
├── config.py
├── collectors/
│   ├── subdomains.py
│   ├── dns.py
│   ├── web.py
│   └── ssl_check.py
├── core/
│   ├── db.py
│   ├── diff.py
│   └── scoring.py
├── data/
├── reports/
└── docs/
```

## Build Roadmap

### Phase 0 - Foundation

* Define scope
* Create repository structure
* Set standards and roadmap

### Phase 1 - Discovery Engine

* Subdomain enumeration
* DNS resolution

### Phase 2 - Web Intelligence

* HTTP checks
* Titles, headers, redirects

### Phase 3 - SSL Intelligence

* Certificate health and expiry checks

### Phase 4 - Storage & Diff Engine

* Save scan snapshots
* Compare current vs previous scans

### Phase 5 - Risk Reporting

* Severity scoring
* Human-friendly reports

## Success Criteria for V1

The project is successful when it can:

* Accept a domain as input
* Discover public assets
* Fingerprint live web assets
* Store results
* Detect changes over time
* Produce a clear report

## Long-Term Vision

CySentra ASM can evolve into:

* Multi-client monitoring platform
* Scheduled scans and alerts
* Web dashboard
* Compliance-focused reporting
* Managed security service offering

## Author

Built by Ibrahim Sheikh / CySentra as a practical cybersecurity engineering initiative.
