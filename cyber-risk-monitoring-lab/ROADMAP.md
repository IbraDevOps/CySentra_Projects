# Roadmap — Cyber Risk & Incident Monitoring Lab

## Phase 0 — Planning (Day 1)
**Outputs*
- Define SMB scenario (assets, users, apps)
- Decide lab topology (VMs / cloud / network)
- Define success criteria + metrics
- Create templates (risk register + incident report)

**Definition of Done**
- Repo initialized with README + ROADMAP + templates
- Lab topology documented

---

## Phase 1 — Asset Inventory + Risk Baseline 
**Tasks**
- Identify assets: endpoints, server, cloud services, accounts
- Threat model: phishing, brute force, malware, data exfil, misconfig
- Create risk register: likelihood × impact scoring
- Map controls: MFA, logging, EDR, backups, change control

**Outputs**
- `docs/architecture.md`
- `docs/risk-register-template.md` filled with initial entries

**Definition of Done**
- 10+ risks documented with rationale + mitigation

---

## Phase 2 — Monitoring Stack (Days 4–6)
**Tasks**
- Deploy Wazuh manager + dashboard (or Wazuh all-in-one)
- Add endpoints:
  - Linux agent (Kali or Ubuntu VM)
  - Windows VM (optional but best)
- Enable rules:
  - Auth failures / brute force
  - Privilege escalation signals
  - Suspicious process execution
- Optional: Suricata/Zeek for network events

**Outputs**
- Screenshots of dashboards + alerts
- Notes on log sources + what’s being collected

**Definition of Done**
- You can generate an alert intentionally and confirm it appears in SIEM

---

## Phase 3 — Attack Simulation + Detection Validation (Days 7–10)
**Simulations (pick 2–3)**
- Brute force / password spraying
- Malware execution (safe test like EICAR or benign script)
- Privilege escalation attempt (Linux: sudo misuse; Windows: suspicious admin actions)
- Data exfil (zip + curl to local HTTP server)

**Outputs**
- `detection_rules/` (if you write custom rules)
- Evidence screenshots and a short timeline

**Definition of Done**
- Each simulation produces observable telemetry + SIEM detection

---

## Phase 4 — Incident Response Case Study (Days 11–14)
Pick ONE incident and write it up like a real analyst:
- Detection
- Triage
- Scope
- Containment
- Eradication
- Recovery
- Lessons learned

**Outputs**
- `incident_report.md` (filled)
- `executive_summary.md` (1-page business summary)

**Definition of Done**
- Full incident package ready as portfolio artifact

---

## Phase 5 — Enhancements (Optional)
- Threat intel enrichment (AbuseIPDB / VirusTotal lookup)
- Alert quality: reduce false positives
- Add MITRE ATT&CK mapping to detections
- Add a simple Python enrichment script
