# OWASP Juice Shop – Web Application VAPT  
**By CySentra Cybersecurity**

## Overview
This project documents a full-scope **Web Application Vulnerability Assessment & Penetration Test (VAPT)**
conducted against OWASP Juice Shop, an intentionally vulnerable application.

The engagement simulates real-world attacker behavior, following OWASP WSTG and OWASP Top 10.

> ⚠️ This project is for educational and authorized testing only.

---

## Target
- Application: OWASP Juice Shop
- Stack:
  - Backend: Node.js + Express
  - Frontend: Angular (SPA)
  - API: REST (JSON)
  - Auth: JWT
- Deployment: Local Docker

---

## Methodology
Aligned with:
- OWASP Web Security Testing Guide (WSTG)
- OWASP Top 10 (2021)

### Phases
1. Reconnaissance
2. Enumeration
3. Client-Side Analysis
4. API Testing
5. Exploitation
6. Risk & Impact Analysis

---

## Key Findings
| Vulnerability | Severity |
|--------------|----------|
| SQL Injection (Auth Bypass) | Critical |
| Broken Access Control | High |
| IDOR | High |
| Stored XSS | High |
| Reflected XSS | High |
| CSRF (Partial) | Medium |

---

## Detailed Report
📄 Full technical report published on Medium:
 [Read the full VAPT report](PASTE_YOUR_MEDIUM_LINK_HERE)

---

## About CySentra
CySentra is a security research and engineering initiative focused on:
- Real-world exploitation
- Manual-first testing
- Actionable remediation

