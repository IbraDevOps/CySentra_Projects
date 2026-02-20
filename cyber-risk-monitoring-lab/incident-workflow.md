Incident Workflow — Phase 3
Objective

Define how alerts are triaged, investigated, and escalated within the SOC environment.

This workflow simulates a realistic small-business SOC operating model.

1️⃣ Alert Generation

Alerts originate from:

Windows Event Logs (Authentication, Privilege Escalation)

Sysmon (Process execution)

Suricata (Network anomalies)

Wazuh FIM (File changes)

Rootcheck module

Severity levels range from 0–15.

Custom severity tiers were defined:

Level	Meaning	Action
1–4	Informational	Log only
5–8	Suspicious	Monitor
9–11	High Risk	Investigate immediately
12–15	Critical	Escalate + Containment
2️⃣ Triage

Analyst checks:

• Rule ID
• Source host
• MITRE ATT&CK mapping
• Frequency of occurrence
• User involved

Questions asked:

Is this expected system behavior?

Is it correlated with other alerts?

Is it repeatable?

3️⃣ Investigation

Depending on alert type:

Authentication anomalies

Check failed login patterns

Check privilege changes

Validate new account creation

Malware / suspicious process

Review process tree

Check parent process

Validate hash reputation

Network anomaly (Suricata)

Identify destination IP/domain

Validate against threat intel

Confirm whether traffic is legitimate

4️⃣ Escalation

Escalation occurs if:

Repeated failed logins

Unauthorized admin creation

Privilege escalation

Lateral movement signals

High-severity rule (>12)

Escalation path:

SOC Analyst → Security Lead → Containment Action

5️⃣ Containment (Simulated)

Possible actions:

Disable account

Isolate endpoint

Block IP at firewall

Terminate malicious process

6️⃣ Post-Incident

Document event

Tune rule (reduce noise if false positive)

Update severity if needed

Improve detection coverage

Outcome of Phase 3

✔ Custom rules deployed
✔ Severity tiers implemented
✔ Noise reduced
✔ Alert escalation defined
✔ SOC workflow documented
