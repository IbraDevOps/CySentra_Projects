Incident Scenario
Simulated privilege escalation through unauthorized user creation.

Detection
Wazuh generated Windows Security alerts (4720 and 4732).

Investigation
Alert triage confirmed a new administrative account was created.

Impact Assessment
Privilege escalation could enable persistence and lateral movement.

Response
Account removed and security controls reviewed.

Lessons Learned
Monitoring for account creation is critical in SMB environments.
