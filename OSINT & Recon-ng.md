# OSINT & External Reconnaissance — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Reconnaissance — Passive & Active Information Gathering
>
> **Tools:** Amass, Subfinder, TheHarvester, Shodan, Google Dorks, LinkedIn, Certificate Transparency
>
> **Real-world impact:** OSINT is the phase that determines how targeted and efficient the rest of the engagement is. Before I touch a single application endpoint, I spend time understanding what the organisation has exposed publicly — subdomains, leaked credentials, exposed infrastructure, technology stack information, and employee details that enable social engineering simulations. In enterprise engagements, the OSINT phase often surfaces findings that are completely independent of the application itself — cloud buckets, staging environments, legacy admin panels — that would never be found by scanning the primary target.

---

## 🧠 Why OSINT Matters Before Touching the Application

The application developers know about `app.company.com`. They do not necessarily know about `dev.company.com` (still running last year's vulnerable version), `backup.company.com` (exposed to the internet with default credentials), or `company.s3.amazonaws.com` (publicly readable S3 bucket with database exports).

OSINT finds what the security team does not know exists.

In professional enterprise engagements, I structure OSINT into three categories: **passive reconnaissance** (no direct contact with target), **semi-passive reconnaissance** (queries to public third-party services), and **active reconnaissance** (direct contact with target infrastructure). This write-up covers the first two — the phases that carry no legal risk and can begin before formal engagement start.

---

## 🔍 Phase 1 — Subdomain Enumeration

Subdomains reveal the full breadth of the organisation's internet footprint — and the forgotten, less-secured corners of it.

### Subfinder (passive, fast)

```bash
# Basic subdomain discovery
subfinder -d company.com -o subfinder_results.txt

# Silent output (subdomains only, no banner)
subfinder -d company.com -silent -o subdomains.txt

# Multiple domains
subfinder -dL domains.txt -o all_subdomains.txt

# With API keys configured (adds many more sources):
# Configure in ~/.config/subfinder/provider-config.yaml
# Sources: Shodan, VirusTotal, Censys, SecurityTrails, etc.
subfinder -d company.com -all -o subfinder_all.txt
```

### Amass (most comprehensive)

```bash
# Passive enumeration (no direct DNS queries to target)
amass enum -passive -d company.com -o amass_passive.txt

# Active enumeration (includes brute force)
amass enum -active -d company.com -o amass_active.txt \
  -brute -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Intel gathering (finds ASNs, IP ranges, related domains)
amass intel -org "Company Name" -o amass_intel.txt
amass intel -ip 1.2.3.4 -o amass_ip.txt

# Visualise the domain tree
amass viz -d company.com -o amass_graph.html
```

### Certificate Transparency (finds subdomains from SSL certs)

```bash
# crt.sh — passive, queries public certificate logs
curl -s "https://crt.sh/?q=%.company.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | \
  sort -u | \
  tee ct_subdomains.txt

# All subdomains ever issued SSL certificates for
# Often finds:
  dev.company.com          → development environment
  staging.company.com      → staging (usually less secured)
  admin.company.com        → admin panel
  api-v1.company.com       → old API version
  jenkins.company.com      → CI/CD system
  vpn.company.com          → VPN portal
  jira.company.com         → Issue tracker (user enumeration)
  confluence.company.com   → Internal wiki
```

### Consolidate and Probe

```bash
# Combine all sources
cat subfinder_results.txt amass_passive.txt ct_subdomains.txt | \
  sort -u > all_subdomains.txt

# Probe which subdomains are live (httpx)
httpx -l all_subdomains.txt -sc -title -o live_subdomains.txt

# Output shows: URL | Status Code | Page Title
# Filter for interesting status codes:
grep " 200 " live_subdomains.txt > live_200.txt
grep " 403 " live_subdomains.txt > live_403.txt  # investigate these
grep " 401 " live_subdomains.txt > live_401.txt  # credentials required
```

> **Enterprise context:** During an engagement, certificate transparency logs revealed `jenkins-prod.company.com` — a Jenkins CI/CD server that was not in the original scope list. The client was surprised it was internet-accessible. The server had default admin credentials (`admin:admin`) and provided full build pipeline access including source code repositories, deployment credentials, and environment variables for all production systems. Subdomain OSINT found what the client's own asset inventory had missed.

---

## 🔍 Phase 2 — Shodan & Censys Intelligence

Shodan and Censys index internet-connected devices — they have already scanned every public IP and stored the responses. You can query this data without sending a single packet to the target.

### Shodan

```bash
# Install CLI
pip install shodan --break-system-packages
shodan init YOUR_API_KEY

# Find all assets for a company (by organisation name)
shodan search org:"Company Name" --fields ip_str,port,hostnames,title

# Find assets by domain
shodan search hostname:company.com

# Find specific technologies
shodan search hostname:company.com product:"Apache httpd"
shodan search hostname:company.com product:"Microsoft IIS"
shodan search org:"Company Name" product:"Spring Boot"

# Find exposed databases
shodan search org:"Company Name" port:3306    # MySQL
shodan search org:"Company Name" port:5432    # PostgreSQL
shodan search org:"Company Name" port:6379    # Redis
shodan search org:"Company Name" port:9200    # Elasticsearch
shodan search org:"Company Name" port:27017   # MongoDB
shodan search org:"Company Name" port:2375    # Docker API

# Find specific IPs
shodan host 1.2.3.4

# Web interface queries at shodan.io:
# org:"Company Name" product:"Cisco" → network devices
# org:"Company Name" http.title:"Admin" → admin panels
# org:"Company Name" ssl.cert.subject.cn:company.com → all SSL assets
```

### Censys

```bash
# Web interface: censys.io (more powerful than CLI for enterprise OSINT)

# Find all IPv4 hosts for a domain
# Search: parsed.names: company.com

# Find web servers by certificate
# Search: parsed.subject.common_name: company.com AND protocols: "443/https"

# Find services by ASN
# Search: autonomous_system.asn: 12345

# Censys surfaces:
# - Services running on non-standard ports
# - Certificate details (subject, SANs, issuer)
# - TLS configuration issues
# - Service banners with version information
```

---

## 🔍 Phase 3 — Google Dorking

Google has indexed content that developers never intended to be public. Dorking finds this content without sending any requests to the target.

```
# High-value enterprise dorks:

# Configuration and sensitive files indexed:
site:company.com filetype:env
site:company.com filetype:config
site:company.com filetype:xml inurl:config
site:company.com filetype:sql
site:company.com filetype:log
site:company.com "DB_PASSWORD" OR "api_key" OR "secret_key"

# Admin and login panels:
site:company.com inurl:admin
site:company.com inurl:login
site:company.com inurl:portal
site:company.com inurl:dashboard
site:company.com inurl:manage
site:company.com intitle:"Admin Panel"

# Exposed documents:
site:company.com filetype:pdf "confidential"
site:company.com filetype:xlsx
site:company.com filetype:docx "internal"

# Error messages and stack traces:
site:company.com "Exception" "stack trace"
site:company.com "SQL syntax" "mysql_fetch"
site:company.com "Warning:" "on line"
site:company.com "Fatal error" filetype:php

# GitHub code search for leaked secrets:
org:company-github-org "api_key"
org:company-github-org "password"
org:company-github-org "DB_PASSWORD"
org:company-github-org filename:.env
org:company-github-org filename:web.config
```

---

## 🔍 Phase 4 — Employee Intelligence & Social Engineering Preparation

In social engineering components of enterprise engagements, employee intelligence shapes the phishing simulation.

```
LinkedIn intelligence:
  → Identify key targets: IT staff, finance, C-suite, HR
  → Find current technology stack from job postings:
    "ASP.NET Core" in job ads → confirms tech stack
    "XYZ LTD" engagement experience → confirms tooling
    "Jenkins, JIRA, Confluence" → maps internal tools
  → Identify recent hires (less security awareness training)

Email format discovery:
  → hunter.io: confirms email format (firstname.lastname@company.com)
  → emailrep.io: validates email addresses
  → Most enterprise formats: first.last@, firstlast@, f.last@

HIBP (Have I Been Pwned) — credential exposure:
  → Check if company domain appears in data breaches
  → api.pwnedpasswords.com → test specific credentials
  → Tells you: employees reuse passwords from breached services
  → Combined with LinkedIn name list = credential stuffing target list

GitHub / GitLab intelligence:
  → Search GitHub for company name, domain, repository names
  → Common leaks: .env files committed accidentally
  → Hard-coded credentials in commit history (even if deleted)
  → Internal tooling and infrastructure code exposed publicly

Tools:
  truffleHog: scans git history for secrets
  gitleaks:   finds secrets in git repos
  gitrob:     maps GitHub organisations and finds sensitive files
```

---

## 🔍 Phase 5 — Passive DNS & IP Range Mapping

```bash
# Find all IPs for a domain
dig +short company.com
dig +short ANY company.com

# Reverse DNS to find related assets on same IP
dig -x 1.2.3.4

# Find ASN and IP ranges
whois 1.2.3.4  → find ASN
bgp.he.net → enter ASN → find all IP ranges

# MX records (email infrastructure)
dig MX company.com
# Reveals: mail providers, hosting infrastructure

# SPF records (reveals cloud providers and email services used)
dig TXT company.com | grep spf
# Example: v=spf1 include:_spf.google.com include:sendgrid.net ~all
# → Company uses Google Workspace and SendGrid

# Find S3 bucket names from DNS
dig CNAME assets.company.com  → assets.s3.amazonaws.com → found bucket name
```

---

## 🗂️ OSINT Workflow Checklist

```
PASSIVE (Zero contact with target):
☐ crt.sh certificate transparency subdomain search
☐ Google dorking for sensitive files and admin panels
☐ GitHub search for exposed secrets and config files
☐ Shodan / Censys passive IP and service mapping
☐ HIBP check for domain in data breaches
☐ LinkedIn for employee and technology intel
☐ Wayback Machine for historical URLs

SEMI-PASSIVE (Third-party queries):
☐ Subfinder subdomain enumeration
☐ Amass passive enumeration
☐ DNS record collection (MX, TXT, CNAME, SPF)
☐ ASN and IP range mapping
☐ httpx to probe which subdomains are live

ANALYSIS:
☐ Map all discovered assets → prioritise by technology and accessibility
☐ Note any staging/dev environments → less secured targets
☐ Identify exposed management interfaces (Jenkins, JIRA, Confluence)
☐ Flag any email addresses found → for phishing simulation scope
☐ Document all findings in recon notes before starting active testing
```

---

## 📋 Enterprise Pentest Report — OSINT Findings Template

**Finding Title:** Exposed Development Environment with Default Credentials — Subdomain OSINT

**Severity:** Critical | **Discovery Method:** Certificate transparency log + httpx probe

```
Discovery:
  crt.sh query for %.company.com returned: dev-portal.company.com
  httpx probe: dev-portal.company.com → HTTP 200 → "Dev Portal - Login"

  Manual testing:
  URL: https://dev-portal.company.com
  Credentials: admin:admin → Login successful
  Access: Full developer portal with database query interface,
          log viewer, and environment variable display

Environment variables visible:
  DB_CONNECTION=sqlserver://PROD-DB01:1433
  DB_PASSWORD=Pr0d_DB_P@ss2024!   ← same as production
  AWS_ACCESS_KEY_ID=AKIA...        ← production AWS key
```

**Business Impact:** Development environment using production credentials enables full access to production database and AWS infrastructure via an unauthenticated path.

---

## 🧭 Key Takeaways

**1. Certificate transparency is the most underused OSINT source in enterprise testing.**
Every SSL certificate issued is logged publicly. Running a crt.sh query takes 10 seconds and returns every subdomain that has ever had an SSL certificate — including staging environments, internal tools, and legacy systems that are no longer linked from anywhere but are still running.

**2. OSINT before the engagement saves time during the engagement.**
An hour of OSINT before the first active scan replaces days of blind enumeration. Knowing the ASN and IP ranges, the subdomain surface, and the technology stack lets me target the right wordlists, the right tools, and the right attack vectors immediately.

**3. GitHub is frequently the most impactful OSINT source for credentials.**
Developers accidentally commit `.env` files, API keys, and credentials to GitHub more often than any other leak vector. A 15-minute GitHub search for the company name + "password" or "api_key" in code has returned Critical findings — live production credentials — in multiple enterprise engagements.

**4. Staging and development environments are always weaker than production.**
OSINT routinely finds dev/staging subdomains that the security team does not know are public. These environments run the same code as production but with less hardening, older versions, default credentials, and more verbose errors. When OSINT finds a staging environment, test it before the production target.

---

## 🔗 References
- [Amass Documentation](https://github.com/owasp-amass/amass)
- [Subfinder GitHub](https://github.com/projectdiscovery/subfinder)
- [crt.sh Certificate Transparency](https://crt.sh)
- [Shodan](https://www.shodan.io)
- [SecLists DNS Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
