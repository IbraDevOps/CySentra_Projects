# IoT Monitoring Plan

## Devices in Scope
- CCTV cameras
- Network printers
- Office routers
- Smart TVs 

---

## Monitoring Method

No agent installation.

Use:
- Suricata for traffic inspection
- DNS logging
- Outbound anomaly detection

---

## Risk Scenarios

- Device contacting foreign C2 servers
- Firmware tampering
- Lateral scanning inside network
- Default credential abuse

---

## Segmentation Plan

Long-term goal:
- Separate IoT VLAN
- Restrict outbound internet access
- Block lateral movement
