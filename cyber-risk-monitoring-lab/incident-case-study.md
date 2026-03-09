# Incident Case Study — Unauthorized Administrative Account Creation

## Incident Summary
During controlled attack simulation within the SOC lab environment, Wazuh generated alerts indicating the creation of a new Windows user account followed by elevation to the local Administrators group. This activity represents a common privilege escalation technique used by attackers to establish persistence and gain administrative control over a compromised endpoint.

## Detection
The activity triggered Windows Security Events **4720 (User Account Created)** and **4732 (Member Added to Local Administrators Group)**.  
These events were ingested by the Wazuh agent and correlated by built-in rule sets, generating high-severity alerts within the SIEM dashboard.

## Investigation
Initial triage confirmed that the account `attacker` had been created locally and immediately granted administrative privileges.  
Review of command execution history indicated the following commands were used during the simulation:

