# Nuclei — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Automated Vulnerability Scanning
>
> **Context:** Nuclei has become one of the most valuable automated scanning tools in my enterprise toolkit. Unlike broad scanners, Nuclei runs targeted, community-verified templates against specific vulnerability patterns — CVEs, misconfigurations, exposed panels, and security headers. I use it in parallel with manual testing: while I work through manual vulnerability testing in Burp, Nuclei is scanning in the background and consistently surfaces misconfiguration findings, exposed admin panels, and known CVEs that would take hours to check manually.

---

## 🧠 Why Nuclei Over Other Automated Scanners

```
Traditional scanners (Nessus, OWASP ZAP active scan):
  → Large, general-purpose, slow
  → High false positive rate
  → Require GUI or complex setup
  → May not have latest CVE templates

Nuclei advantages:
  → Template-based: each template targets ONE specific vulnerability
  → Community-maintained: 6,000+ templates updated regularly
  → Fast: parallel execution across templates
  → Low false positives: templates are verified before publication
  → CLI-first: integrates naturally into automation pipelines
  → Customisable: write your own templates in YAML

Enterprise use case:
  → Background scanning during manual testing engagement
  → CVE verification on discovered service versions
  → CI/CD pipeline integration for continuous scanning
  → Rapid enumeration of known misconfiguration patterns
```

---

## ⚙️ Setup and Template Management

```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Or: apt install nuclei (Kali)

# Update templates (run before every engagement):
nuclei -update-templates
# Downloads to: ~/.local/nuclei-templates/

# List available template categories:
ls ~/.local/nuclei-templates/
# cves/          exposures/     misconfiguration/
# vulnerabilities/ technologies/  default-logins/
# takeovers/     network/       dns/

# Count templates by category:
nuclei -list-templates | grep "cves" | wc -l
```

---

## 🔧 Core Scan Commands for Enterprise Engagements

### Standard Enterprise Web App Scan

```bash
# Balanced scan — good coverage without being noisy
nuclei -u https://app.company.com \
  -t misconfiguration \
  -t exposures \
  -t default-logins \
  -t technologies \
  -severity medium,high,critical \
  -o nuclei_initial.txt \
  -nc

# Full scan on confirmed test environment
nuclei -u https://app.company.com \
  -t ~/.local/nuclei-templates/ \
  -severity medium,high,critical \
  -o nuclei_full.txt \
  -nc \
  -c 25 \
  -rate-limit 50

# Flag explanation:
# -t:          template directory or category
# -severity:   filter by severity
# -o:          output file
# -nc:         no colour (cleaner for file output)
# -c 25:       25 parallel workers
# -rate-limit 50: max 50 req/sec (conservative for shared environments)
```

### Targeted CVE Scanning

```bash
# Scan for specific CVE after Nmap identifies a vulnerable version

# Log4Shell (CVE-2021-44228) — Apache Log4j
nuclei -u https://app.company.com \
  -t cves/2021/CVE-2021-44228.yaml \
  -v

# Spring4Shell (CVE-2022-22965) — Spring Framework RCE
nuclei -u https://app.company.com \
  -t cves/2022/CVE-2022-22965.yaml \
  -v

# All 2021-2024 critical CVEs:
nuclei -u https://app.company.com \
  -t cves/2021/ \
  -t cves/2022/ \
  -t cves/2023/ \
  -t cves/2024/ \
  -severity critical,high \
  -o cve_scan.txt

# Scan all Apache/Struts CVEs:
nuclei -u https://app.company.com \
  -t cves/ \
  -tags struts,apache \
  -o apache_cves.txt

# Technology-specific CVE scanning after fingerprinting:
# WordPress:
nuclei -u https://app.company.com -tags wordpress -o wp_scan.txt

# Jenkins:
nuclei -u https://jenkins.company.com -tags jenkins -o jenkins_scan.txt

# Spring Boot:
nuclei -u https://app.company.com -tags springboot -o spring_scan.txt

# Jira:
nuclei -u https://jira.company.com -tags jira -o jira_scan.txt
```

### High-Value Misconfiguration Templates

```bash
# Exposed panels and dashboards (critical enterprise targets):
nuclei -u https://app.company.com \
  -t exposures/panels/ \
  -o panels_scan.txt

# Default login credentials check:
nuclei -u https://app.company.com \
  -t default-logins/ \
  -o default_logins.txt

# Exposed configuration files (.env, web.config, etc.):
nuclei -u https://app.company.com \
  -t exposures/configs/ \
  -o configs_scan.txt

# Cloud metadata endpoints (AWS, Azure, GCP):
nuclei -u https://app.company.com \
  -t cloud-metadata/ \
  -o cloud_metadata.txt

# Security headers check:
nuclei -u https://app.company.com \
  -t misconfiguration/http-missing-security-headers.yaml \
  -o headers.txt

# Exposed git repositories:
nuclei -u https://app.company.com \
  -t exposures/git-config.yaml \
  -o git_exposure.txt

# CORS misconfiguration:
nuclei -u https://app.company.com \
  -t misconfiguration/cors-misconfiguration.yaml \
  -o cors_scan.txt
```

### Bulk Scanning Multiple Targets

```bash
# Scan all live subdomains discovered during OSINT:
nuclei -l live_subdomains.txt \
  -t misconfiguration/ \
  -t exposures/ \
  -t default-logins/ \
  -severity medium,high,critical \
  -o nuclei_all_subdomains.txt \
  -nc \
  -c 20 \
  -rate-limit 30

# Scan with authenticated session:
nuclei -u https://app.company.com \
  -t vulnerabilities/ \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..." \
  -H "Cookie: session=abc123" \
  -o nuclei_authenticated.txt
```

---

## ✍️ Writing Custom Templates for Enterprise-Specific Checks

```yaml
# Custom template — check for Spring Boot Actuator
id: spring-actuator-env-exposed

info:
  name: Spring Boot Actuator /env Exposed
  author: Dheeraj Kumar Jayaswal
  severity: critical
  description: Spring Boot Actuator /actuator/env endpoint is accessible
               without authentication, exposing all environment variables.
  tags: springboot,actuator,exposure,misconfig

requests:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/manage/env"
      - "{{BaseURL}}/application/env"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "propertySources"
          - "systemEnvironment"
        condition: or

      - type: word
        words:
          - "application/json"
        part: header
```

```yaml
# Custom template — CORS wildcard misconfiguration
id: cors-wildcard-with-credentials

info:
  name: CORS Wildcard with Credentials Allowed
  author: Dheeraj Kumar Jayaswal
  severity: high
  description: Access-Control-Allow-Origin is wildcard (*) and
               Access-Control-Allow-Credentials is true.
  tags: cors,misconfig

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/users/me"

    headers:
      Origin: "https://evil.example.com"

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: *"

      - type: word
        part: header
        words:
          - "Access-Control-Allow-Credentials: true"
```

---

## 🔄 CI/CD Pipeline Integration

```yaml
# GitHub Actions — Nuclei scan on every deployment
name: Security Scan — Nuclei DAST

on:
  push:
    branches: [main]

jobs:
  nuclei-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run Nuclei
        uses: projectdiscovery/nuclei-action@main
        with:
          target: https://staging.company.com
          flags: >
            -t misconfiguration
            -t exposures
            -t default-logins
            -severity medium,high,critical
            -rate-limit 20

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: nuclei-results
          path: nuclei-output.txt
```

---

## 📋 Enterprise Report Template

```
Finding Title: Spring Boot Actuator /actuator/env Exposed — Environment Variables Accessible

Severity: Critical | CVSS: 9.8

Discovery: Nuclei automated scan
Template: nuclei-templates/exposures/configs/springboot-actuator-env.yaml

Command:
  nuclei -u https://app.company.com \
    -t exposures/configs/ \
    -severity critical -v

Output:
  [critical] [springboot-actuator-env] [http] https://app.company.com/actuator/env

Verification (manual):
  GET /actuator/env → HTTP 200
  Response contains: SPRING_DATASOURCE_PASSWORD, AWS_SECRET_ACCESS_KEY, JWT_SECRET

(See Security Misconfiguration write-up for full exploitation details)
```

---

## 🧭 Key Takeaways

**1. Run Nuclei in the background during every engagement.**
Start Nuclei scanning while you configure Burp and begin manual testing. By the time you finish the application walkthrough, Nuclei has already checked 6,000+ known vulnerability patterns. The combination of automated breadth and manual depth is what makes enterprise testing comprehensive.

**2. Always update templates before an engagement.**
`nuclei -update-templates` takes 30 seconds. New CVE templates are added weekly. A template published last month for a Spring Framework vulnerability could be the Critical finding in today's engagement. Stay current.

**3. Technology tags dramatically focus scan time.**
If you know the application uses Jenkins, running `nuclei -tags jenkins` scans only Jenkins-relevant templates — much faster than scanning all templates. Technology fingerprinting from Phase 1 of recon directly informs your Nuclei tag selection.

**4. Nuclei findings still require manual verification before reporting.**
Nuclei templates are good but not perfect. A `[critical]` output from Nuclei is a confirmed lead, not a confirmed finding. Verify every Nuclei result manually in Burp Repeater before adding it to the report.

---

## 🔗 References
- [Nuclei Documentation](https://docs.projectdiscovery.io/tools/nuclei)
- [Nuclei Templates GitHub](https://github.com/projectdiscovery/nuclei-templates)
- [ProjectDiscovery Cloud](https://cloud.projectdiscovery.io)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
