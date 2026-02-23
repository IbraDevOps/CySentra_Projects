# Network Monitoring Strategy

## Current State
Suricata running on Ubuntu VM.
Currently monitoring only VM interface traffic.

---

## Target State

### Phase 1
- Enable router syslog forwarding to Wazuh.
- Monitor firewall events and external connection attempts.

### Phase 2
- Deploy Suricata in bridge or network tap mode.
- Monitor entire office subnet.

---

## Detection Goals

- Port scans
- DNS tunneling
- Suspicious outbound connections
- Lateral movement
- IoT device anomalies
