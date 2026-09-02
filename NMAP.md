# Nmap — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Network Discovery & Port Scanning
>
> **Context:** Nmap is the first active tool I run against any enterprise target. Before testing a single web application vulnerability, I need to know what services are listening, what versions are running, and what the network topology looks like. In enterprise engagements — particularly those with internal network access — Nmap tells me what attack surface exists beyond the web application the client wants tested.

---

## 🔍 Core Scan Types — When I Use Each

```
Scan type decision tree for enterprise engagements:

  Is target internet-facing?
    Yes → -sS (SYN scan) or -sT (TCP connect — when no root)
  
  Do I need service versions?
    Yes → add -sV
  
  Do I need OS detection?
    Yes → add -O (requires root)
  
  Is stealth important (shared prod environment)?
    Yes → reduce timing: -T2 instead of default -T3
  
  Is speed important (isolated test environment)?
    Yes → increase timing: -T4, add --min-rate
```

---

## 🔧 Scan Commands for Enterprise Engagements

### Phase 1 — Discovery (What Is Alive)

```bash
# Ping sweep — find live hosts in a subnet
nmap -sn 10.0.0.0/24 -oN host_discovery.txt
# -sn: no port scan, just host discovery
# Output: list of live IP addresses

# If ICMP is blocked (common in enterprise networks):
nmap -sn -PS22,80,443,8080 10.0.0.0/24 -oN host_discovery.txt
# -PS: TCP SYN ping on specified ports — finds hosts even when ICMP blocked

# Faster discovery with masscan (for large ranges):
masscan -p80,443,8080,8443 10.0.0.0/16 --rate=1000 -oG masscan_out.txt
```

### Phase 2 — Port Scanning

```bash
# Standard enterprise web application assessment scan
# Covers all common web, management, and database ports:
nmap -sS -p 21,22,23,25,53,80,110,135,139,143,443,445,\
3306,3389,5432,5900,6379,8080,8443,8888,9200,27017 \
  -sV --version-intensity 5 \
  -O \
  -T3 \
  --open \
  -oA nmap_targeted \
  target.company.com

# Full port scan (all 65535 ports — use on dedicated test environments)
nmap -sS -p- \
  --open \
  -T4 \
  --min-rate 5000 \
  -oA nmap_fullport \
  target.company.internal

# UDP scan — often missed, surfaces SNMP, DNS, TFTP exposures
nmap -sU \
  -p 53,67,68,69,111,123,135,137,138,161,162,500,514,1900 \
  --open \
  -T3 \
  -oA nmap_udp \
  target.company.com
```

### Phase 3 — Service Version & OS Detection

```bash
# Aggressive version detection on discovered open ports
nmap -sV \
  --version-intensity 9 \
  -O \
  -p [OPEN_PORTS_FROM_PREVIOUS_SCAN] \
  -oA nmap_versions \
  target.company.com

# Output interpretation:
# 443/tcp  open  ssl/https  Microsoft IIS httpd 8.5
#   → IIS 8.5: check CVE-2015-1635 (MS15-034) HTTP.sys RCE
# 6379/tcp open  redis  Redis key-value store
#   → Redis with no auth = unauthenticated data access
# 9200/tcp open  http  Elasticsearch 7.x
#   → Elasticsearch: check if auth required
# 2375/tcp open  docker  Docker API
#   → Unauthenticated Docker API = container escape = host RCE
```

### Phase 4 — NSE Script Scanning

```bash
# Vulnerability detection scripts (safe, non-exploiting)
nmap --script vuln \
  -p [OPEN_PORTS] \
  -oA nmap_vuln \
  target.company.com

# HTTP-specific scripts (most useful for web app engagements)
nmap --script http-title,http-headers,http-methods,\
http-auth,http-robots.txt,http-config-backup,\
http-git,http-shellshock \
  -p 80,443,8080,8443 \
  -oA nmap_http \
  target.company.com

# SSL/TLS audit (weak ciphers, expired certs, POODLE, BEAST)
nmap --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle \
  -p 443,8443 \
  -oA nmap_ssl \
  target.company.com

# SMB vulnerability check (internal network)
nmap --script smb-vuln-ms17-010,smb-security-mode \
  -p 445 \
  10.0.0.0/24 \
  -oA nmap_smb

# DNS enumeration
nmap --script dns-brute \
  -p 53 \
  --script-args dns-brute.domain=company.com \
  -oA nmap_dns \
  ns1.company.com

# Default credential detection
nmap --script http-default-accounts \
  -p 80,443,8080,8443 \
  -oA nmap_defaultcreds \
  target.company.com
```

---

## 🏢 Enterprise-Specific Scan Scenarios

### Scenario 1 — Web Application Engagement (External)

```bash
# My standard opening scan for external web app engagements:

# Step 1: Quick service discovery
nmap -sS --open -T4 \
  -p 21,22,25,53,80,110,143,443,3389,8080,8443,9090,9200 \
  -oA nmap_quick target.company.com

# Step 2: Version detection on discovered open ports
nmap -sV -sC -O \
  -p [PORTS_FOUND_IN_STEP_1] \
  -oA nmap_detailed target.company.com

# Step 3: SSL/TLS quality check
nmap --script ssl-enum-ciphers -p 443,8443 target.company.com

# Typical findings from this sequence:
# → TLS 1.0/1.1 still enabled = SSL/TLS misconfiguration finding
# → HTTP methods: PUT, DELETE enabled = HTTP method abuse possible
# → http-git: /.git/ accessible = source code exposure
# → http-config-backup: web.config.bak found = credential exposure
```

### Scenario 2 — Internal Network Assessment

```bash
# Broader sweep when given VPN access to internal network:

# Step 1: Identify live hosts in scope subnet
nmap -sn 10.0.14.0/24 -oG - | grep "Up" | awk '{print $2}' > live_hosts.txt

# Step 2: Port scan all live hosts for common services
nmap -sS --open -T3 \
  -p 22,80,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200 \
  -iL live_hosts.txt \
  -oA nmap_internal

# Step 3: Flag high-risk findings immediately
# Look for these in output:
grep -E "6379|9200|27017|2375|5900" nmap_internal.gnmap
# Redis (6379), Elasticsearch (9200), MongoDB (27017),
# Docker API (2375), VNC (5900) — all commonly unauthenticated
```

### Scenario 3 — Rate-Limited Production Scan

```bash
# When client has WAF/IDS that triggers on fast scanning:
nmap -sT \           # TCP connect (stealth less important)
  -T2 \             # Polite timing
  --scan-delay 1s \ # 1 second between probes
  -p 80,443 \       # Only confirmed in-scope ports
  --max-retries 1 \ # Reduce retries
  -oA nmap_gentle \
  target.company.com
```

---

## 📊 Reading Nmap Output Effectively

```bash
# Parse grepable output for rapid analysis:
# Find all open ports across all hosts:
grep "open" nmap_scan.gnmap | grep -oP "\d+/open" | sort -t/ -k1 -n | uniq -c | sort -rn

# Extract all hosts with a specific port open:
grep "9200/open" nmap_scan.gnmap | awk '{print $2}'  # All Elasticsearch
grep "6379/open" nmap_scan.gnmap | awk '{print $2}'  # All Redis

# Convert XML output to CSV for reporting:
nmap -oX scan.xml ... 
xsltproc /usr/share/nmap/nmap.xsl scan.xml -o scan.html

# Import to Metasploit:
db_import scan.xml  # After msfconsole and db_connect
```

---

## 📋 Enterprise Report — Nmap Findings Template

```
Finding Title: Unauthenticated Redis Instance Exposed on Internal Network

Severity: Critical | CVSS: 9.8

Discovery:
  nmap -sV -p 6379 10.0.14.0/24
  Output: 10.0.14.55  6379/tcp open redis Redis 6.2.1

Verification:
  redis-cli -h 10.0.14.55
  10.0.14.55:6379> INFO server
  → Full server information returned without authentication

Impact:
  Unauthenticated Redis access allows reading all cached data
  (session tokens, API keys, user data), writing arbitrary cache entries
  (session hijacking), and potentially RCE via Redis config write to cron.

Remediation:
  requirepass <strong_password> in redis.conf
  bind 127.0.0.1 (restrict to localhost unless inter-service needed)
  Network: firewall port 6379 to application servers only
```

---

## 🧭 Key Takeaways

**1. Always scan for service versions — default Nmap output is insufficient for reports.**
`-sV` turns "6379/tcp open" into "6379/tcp open redis Redis 6.2.1". The version is what maps to CVEs. A Critical finding requires knowing the exact version is vulnerable.

**2. Save all output in all formats: `-oA scan_name`.**
`-oA` creates `.nmap` (human-readable), `.gnmap` (greppable), and `.xml` (parseable) simultaneously. The XML imports directly into Metasploit and reporting tools. Never run a scan without saving output.

**3. UDP scanning is consistently neglected — and consistently productive.**
SNMP on UDP/161 with community string "public" provides detailed device configuration and network topology. It takes longer than TCP but surfaces findings that TCP-only scanning misses entirely.

**4. NSE scripts double your findings with one extra flag.**
`--script vuln` on discovered open ports runs safe detection scripts for hundreds of known vulnerabilities. The `http-git` script alone finds /.git/ exposure. Takes a few extra minutes and consistently surfaces reportable findings.

---

## 🔗 References
- [Nmap Official Documentation](https://nmap.org/docs.html)
- [Nmap NSE Script Reference](https://nmap.org/nsedoc/)
- [Nmap Network Scanning Book](https://nmap.org/book/)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
