# Initial Risk Hypothesis

## High-Risk Areas

### API Authorization
Potential BOLA/IDOR vulnerabilities in transaction and wallet endpoints.

### Authentication
Potential JWT/session weaknesses.

### Business Logic
Potential transaction manipulation or replay abuse.

### Privilege Escalation
Potential improper role enforcement.

### Exposed Services
Public API services on ports 3005 and 3017 require deeper validation.

### Admin Exposure
Potential hidden admin/debug endpoints.

### Blockchain Risks
Smart contract access control and escrow logic require review.

### Operational Security
Potential weak secret management or infrastructure hardening gaps.

## Special Focus
Client reported prior suspected compromise requiring deeper investigation.
