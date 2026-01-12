RAW_NET_SOC — Open-Source SOC Architecture (Small Office)
Overview

RAW_NET_SOC is an open-source Security Operations Center (SOC) project designed for a SME business office environment.
The goal is to build realistic SOC visibility using only open-source tools, starting from endpoint detection and expanding into network monitoring and threat intelligence.

This repository documents architecture, design decisions, and deployment strategy  not sensitive credentials or live configurations.

 Objectives

Centralize security logs from endpoints

Detect malicious activity like auth abuse, malware, persistence

Correlate events and generate alerts

Enrich detections with threat intelligence

Scale gradually from 1 machine to full office

 High-Level Architecture

 
 Endpoints (Windows/Linux
        │
        │  (Wazuh Agent)
        ▼


        
 Wazuh Manager 
        │
        │  (Filebeat / Indexing)
        ▼

        
 Elasticsearch 
        │
        ▼


        
 Kibana Dashboards & Alerts 



 MISP 
  └── Threat Intelligence (IOCs, Feeds)
      ↳ Enrichment for detections




[ Network Sensor ]
  └── Zeek / Suricata → Elasticsearch

  

 Virtual Machines
VM	Purpose	Components
VM-1	Log Storage & Visualization	Elasticsearch, Kibana
VM-2	Detection & SIEM	Wazuh Manager, API
VM-3	Threat Intelligence	MISP
VM-4 	Network Visibility	Zeek / Suricata



Initial deployment uses VM-1 + VM-2 only. Others are added later.

 Data Sources

Endpoint logs like Windows Event Logs, Sysmon

Linux audit logs

Authentication activity

File integrity monitoring

 Network metadata & IDS alerts




 Deployment Phases
Phase 1 — Endpoint Core  SOC 

Install Wazuh Manager

Deploy Wazuh Agent on one Windows machine

Enable Sysmon

Verify alerts & dashboards




Phase 2 — Scale Endpoints

Roll out agents to remaining office PCs

Tune rules & reduce noise




Phase 3 — Threat Intelligence

Deploy MISP

Add curated feeds

Correlate IOCs with alerts




Phase 4 — Network Monitoring (Optional)

Add Zeek / Suricata

Monitor traffic via SPAN/mirror

Correlate with endpoint events

 Security Notes

No credentials, secrets, or live IPs stored in this repo

Configs shared are sanitized and generic

Designed for defensive security only
