# Nessus — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Vulnerability Assessment Scanner
>
> **Context:** Nessus is the industry standard vulnerability scanner in enterprise environments — not because it replaces manual testing, but because it efficiently surfaces known CVEs, missing patches, and configuration weaknesses across large IP ranges. At Infosys, I use Nessus for network-layer vulnerability assessment within internal assessments, specifically to enumerate patching gaps and known service vulnerabilities that would take days to manually verify across a 200-host internal network.

---

## 🧠 Nessus in the Enterprise Testing Workflow

```
Where Nessus fits:

Manual testing (Burp + Nuclei + custom):
  → Application logic flaws
  → Business logic vulnerabilities
  → Complex injection chains
  → IDOR, authentication bypass
  → Anything that requires understanding context

Nessus:
  → Missing OS and software patches (CVEs)
  → Service-level misconfigurations at scale
  → SSL/TLS configuration weaknesses
  → Default credentials on network services
  → Compliance gaps (PCI-DSS, CIS benchmarks)
  → Coverage across large internal IP ranges efficiently

The combination: Nessus for breadth, manual testing for depth.
```

---

## ⚙️ Scan Policy Configuration for Enterprise Engagements

### Pre-Scan Setup

```
1. Create engagement-specific scan policy:
   New Scan → Advanced Scan
   Name: ClientName_Internal_Assessment_2025

2. Scope configuration:
   Targets: 10.0.14.0/24 (or paste host list)
   Exclude: any explicitly out-of-scope hosts

3. Credentials (for authenticated scanning — much better coverage):
   Credentials tab → SSH → add key or username/password
   Credentials tab → Windows → SMB credentials if provided
   Authenticated scans find 3-5x more vulnerabilities than unauthenticated

4. Port scan settings:
   Port scan range: default (1-65535 for thorough, common ports for fast)
   Scanner: TCP Scan + UDP Scan (check SNMP, DNS)
   Max simultaneous hosts: 5 (conservative for shared environments)
   Max simultaneous checks per host: 5

5. Plugin selection:
   For web app engagements:
   → Enable: Web Servers, HTTP, HTTPS, Application Servers
   → Enable: General, Service Detection
   → Disable: DoS plugins (Policy Compliance → uncheck Denial of Service)
```

---

## 🔧 Scan Templates for Enterprise Scenarios

### Template 1 — Internal Network Assessment

```
Template: Advanced Scan
Scope: Full internal subnet (10.0.0.0/24)

Key plugin families to enable:
  ✓ General (service detection, versions)
  ✓ Web Servers (Apache, IIS, Nginx CVEs)
  ✓ Application Servers (Tomcat, JBoss, WebSphere)
  ✓ Databases (MySQL, MSSQL, Oracle, PostgreSQL)
  ✓ Windows (Windows Update, SMB, RDP)
  ✓ Default Unix Accounts
  ✓ Default Windows Accounts
  ✓ SSL/TLS (cipher suites, certificate issues)
  ✗ Disable: Denial of Service plugins (never in production)
  ✗ Disable: Brute Force (use Hydra with controlled wordlists instead)

Expected scan duration: 2-4 hours for /24 subnet
```

### Template 2 — Web Server Focused Scan

```
Template: Web Application Tests
Scope: Specific web server IPs

Key findings this surfaces:
  → Outdated web server versions with CVEs
  → Missing security headers
  → SSL/TLS misconfiguration
  → Default pages (IIS default, Apache test page)
  → Dangerous HTTP methods (PUT, DELETE enabled)
  → Directory listing enabled
  → Exposed server-status, server-info pages
  → Known web application CVEs (Struts, Spring, Log4j)

Run alongside manual Burp testing for maximum coverage.
```

### Template 3 — Credentialed Patch Audit

```
Template: Credentialed Patch Audit
Requires: SSH credentials (Linux) or SMB credentials (Windows)

What credentialed scanning adds:
  → Installed software versions (not just banner-detected)
  → Missing OS patches and security updates
  → Local configuration issues not visible remotely
  → User account configuration
  → File permission issues
  → Registry settings (Windows)
  → Service configuration details

Credentialed vs Unauthenticated coverage comparison:
  Unauthenticated: ~200 findings typical
  Credentialed:    ~800 findings typical (same host)
  The difference: credentialed scanning is dramatically more accurate
```

---

## 📊 Interpreting Nessus Results Professionally

```
Nessus severity ratings vs what they mean in enterprise context:

Critical (CVSS 9.0-10.0):
  → Immediately exploitable with public exploits
  → Examples: EternalBlue MS17-010, Log4Shell, Spring4Shell
  → Action: Flag immediately, confirm manually, escalate to client
  → Include in executive summary regardless of other findings

High (CVSS 7.0-8.9):
  → Serious vulnerability, exploit may require conditions
  → Examples: Outdated OpenSSH, old Apache with known RCE
  → Action: Manually verify, include in main findings section

Medium (CVSS 4.0-6.9):
  → Meaningful risk but not immediately critical
  → Examples: Missing patches, weak TLS configuration
  → Action: Include in report, prioritise for remediation

Low (CVSS 0.1-3.9):
  → Informational or minor risk
  → Examples: Missing security headers, version disclosure
  → Action: Include in appendix, low remediation priority

Information:
  → Service detection, configuration details
  → Action: Use for context, do not report as vulnerabilities
```

### Filtering Results for Report-Ready Findings

```
In Nessus UI — Vulnerabilities tab:

Filter 1: Severity = Critical, High
→ These go in the main findings section

Filter 2: Severity = Medium
→ Verify each manually before including

Filter 3: Plugin family = Web Servers
→ Review all for application-relevant findings

Filter 4: Search for "default" in plugin name
→ Default credentials findings = immediately test manually

Filter 5: Exclude plugin IDs that are known false positives
→ Build an exclusion list over time per environment

Export filtered results:
  Report → Generate Report → PDF or CSV
  CSV useful for tracking remediation status
```

---

## 🔍 Manual Verification of Nessus Findings

```
The golden rule: Every Nessus Critical and High finding
requires manual verification before it goes in the report.

Verification workflow for common finding types:

Nessus: "MS17-010 EternalBlue SMB RCE"
  Verify: nmap --script smb-vuln-ms17-010 -p 445 [IP]
  Or: Metasploit auxiliary/scanner/smb/smb_ms17_010

Nessus: "Apache 2.4.49 Path Traversal CVE-2021-41773"
  Verify: curl "https://target/cgi-bin/.%2e/.%2e/.%2e/etc/passwd"
  → 200 response with /etc/passwd content = confirmed

Nessus: "SSL/TLS Certificate Expired"
  Verify: openssl s_client -connect target:443 -showcerts
  → Check Not After date in certificate output

Nessus: "Default Credentials — admin:admin"
  Verify: Manual login attempt in browser
  → Successful login = confirmed, screenshot as evidence

Nessus: "Directory Listing Enabled"
  Verify: Browse directly to path in browser or curl
  → Returns HTML directory listing = confirmed

Never report: "Nessus Plugin 12345 flagged this as High"
Always report: "Manual verification confirmed X is vulnerable to Y"
```

---

## 📋 Enterprise Report — Nessus-Sourced Finding

```
Finding Title: Missing Critical Security Patches — Apache Struts CVE-2017-5638

Severity: Critical | CVSS: 10.0

Discovery: Nessus credentialed scan (Plugin ID: 99546)
Verification: Manual confirmation via Nuclei template + manual HTTP test

Affected host: legacy-portal.company.internal (10.0.14.88)
Service: Apache Struts 2.3.31 on port 443

Nessus finding:
  Plugin: Apache Struts Multiple Vulnerabilities (CVE-2017-5638)
  Severity: Critical
  Plugin output: Remote Code Execution via Content-Type header

Manual verification:
  nuclei -u https://10.0.14.88 -t cves/2017/CVE-2017-5638.yaml
  Result: [critical] [CVE-2017-5638] [http] https://10.0.14.88

  Manual HTTP test:
  Content-Type: %{(#_='multipart/form-data')...OGNL_PAYLOAD...}
  Response: Server executed command, returned hostname output

Impact: Unauthenticated RCE on internal application server.

Remediation: Upgrade Apache Struts to 2.5.30+ immediately.
```

---

## 🧭 Key Takeaways

**1. Credentialed scans are the professional standard — push for credentials.**
The difference between credentialed and unauthenticated Nessus scans is like the difference between an X-ray and a surface physical exam. Always request SSH and Windows credentials for Nessus scans in enterprise assessments. The findings are more accurate, more complete, and more actionable.

**2. Nessus is a lead generator — manual verification closes the loop.**
A Critical Nessus finding is the start of the finding workflow, not the end. Verify it manually, confirm it is real, document the verification steps. This is what separates a professional pentest report from a Nessus PDF export.

**3. Sort by CVSS and filter to Critical+High first — the rest is noise.**
Nessus on a 200-host network can return 10,000 findings. Most are Medium or Low — missing patches that are important but not immediately exploitable. Start with Critical, manually verify each, then work down. The executive summary only needs Critical and High.

**4. Share filtered Nessus reports with the remediation team.**
After the engagement, export the CSV filtered to Critical and High, sorted by host. Give this to the sysadmin team as a patching priority list. This makes your pentest immediately actionable beyond just the security team.

---

## 🔗 References
- [Tenable Nessus Documentation](https://docs.tenable.com/nessus/)
- [Nessus Plugin Library](https://www.tenable.com/plugins)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
