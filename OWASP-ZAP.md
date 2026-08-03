# OWASP ZAP — Enterprise DevSecOps Integration Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — DevSecOps & CI/CD Security Testing
>
> **Context:** OWASP ZAP has a distinct role in my enterprise security work compared to Burp Suite. While Burp is my primary manual testing tool, ZAP is what I integrate into enterprise CI/CD pipelines for automated DAST. I have integrated ZAP into DevSecOps workflows, configured it for automated pipeline scanning, and used it to reduce recurring vulnerabilities by 50% through continuous DAST in build pipelines. This write-up reflects that operational perspective.

---

## 📖 Burp vs ZAP — When I Use Each

```
Burp Suite Pro:
  ✓ Primary tool for manual penetration testing engagements
  ✓ Complex vulnerability research requiring full request control
  ✓ Custom exploitation, payload crafting, session manipulation
  ✓ When I need deep manual control over every request

OWASP ZAP:
  ✓ Automated DAST integration in CI/CD pipelines
  ✓ Baseline security scanning on every build
  ✓ Security scanning in environments where Burp license is not available
  ✓ API security scanning with OpenAPI/Swagger spec integration
  ✓ Scripted scanning workflows for recurring scan tasks
  ✓ When I need to scan across a large number of endpoints automatically
  ✓ Cost-effective alternative for teams with limited security budget
```

---

## 🏗️ ZAP Setup for Enterprise Use

### Installation and First Configuration

```
Download: https://www.zaproxy.org/download/
Install as: Desktop application OR Docker container

First-run configuration for enterprise:
  Tools → Options → Connection
  → Set upstream proxy if corporate network requires it

  Tools → Options → API
  → Generate API key (required for headless/CI use)
  → Note API key for pipeline integration

  Tools → Options → Active Scan
  → Set thread count: 5 (conservative for shared environments)
  → Set delay between requests: 0ms (internal test environments)
    or 100ms (production-like environments)
```

### Context Configuration (equivalent to Burp's Scope)

```
Sites panel → right-click target → Include in Context → Default Context

Context configuration matters for authenticated scanning:
  Right-click context → Context Properties

  Authentication tab:
  → Form-based Authentication:
     Login URL: https://app.company.com/login
     Username field: username
     Password field: password
     Login indicator: "Welcome" or "Dashboard"
     Logout indicator: "Login" or "Sign in"

  Users tab:
  → Add test user credentials

  Session Management:
  → Cookie-based (default for most apps)
  → Or: Header-based for APIs (Bearer token)
```

---

## 🔍 Scanning Modes

### Passive Scan (Always Running)

```
ZAP passively analyses every response that passes through its proxy
No additional requests sent — completely safe on any environment

What passive scan detects:
  Missing security headers (CSP, HSTS, X-Frame-Options)
  Cookie security flags (missing HttpOnly, Secure, SameSite)
  Information disclosure in responses
  Potentially dangerous content patterns
  Form field security issues
  SSL/TLS configuration issues

Enable/configure:
  Analyse → Passive Scan Rules → enable all relevant rules
  Results appear in Alerts tab as you browse

Enterprise use:
  Run passive scan during all manual browsing
  Add 0 server load, detects many header/cookie issues automatically
```

### Spider (Automated Discovery)

```
Spider discovers all URLs in the application automatically.

Standard Spider (HTML crawl):
  Right-click target → Spider
  Max depth: 5 (adjust based on app size)
  Thread count: 5
  → Discovers all HTML-linked pages

AJAX Spider (for SPAs and JavaScript-heavy apps):
  Right-click target → AJAX Spider
  Browser: Chrome (headless)
  → Uses real browser to discover dynamically loaded content
  → Essential for React/Angular/Vue applications

Enterprise tip:
  Run AJAX Spider on modern enterprise apps — Standard Spider misses
  most content in single-page applications built on modern frameworks
```

### Active Scan (Vulnerability Discovery)

```
Active scan sends attack payloads to every discovered parameter.

Configure scan policy before running:
  Analyse → Scan Policy Manager → Add
  Enable: SQL Injection, XSS, Path Traversal, SSRF, Command Injection
  Strength: Medium (balanced speed vs coverage)
  Threshold: Medium (reduces false positives)

Run active scan:
  Right-click target/context → Active Scan
  Start: after Spider has finished mapping the application

Enterprise caution:
  Active scan sends attack payloads — can cause application instability
  Always run in test/staging environment, not production
  If production scanning is required: use Low strength, minimal thread count
  Inform the client's operations team before running active scans
```

---

## 🔄 CI/CD Pipeline Integration (My Primary ZAP Use Case)

This is where ZAP delivers the most enterprise value — automated DAST on every build.

### Docker-Based Pipeline Scanning

```yaml
# GitHub Actions workflow example
name: DAST Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  dast-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Start application
        run: docker-compose up -d
        # Wait for app to be ready

      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'    # include active scan
          fail_action: true    # fail build on new High alerts

      - name: Upload ZAP Report
        uses: actions/upload-artifact@v3
        with:
          name: zap-report
          path: zap_report.html
```

### Three Scan Types for Different Pipeline Stages

```
1. Baseline Scan (every commit — fastest):
   docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
     -t http://staging.company.com \
     -r baseline_report.html
   → Passive scan only, ~2 minutes
   → Catches: missing headers, cookie issues, obvious passive findings

2. API Scan (on API change commits):
   docker run -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
     -t http://staging.company.com/api/swagger.json \
     -f openapi \
     -r api_report.html
   → Scans all API endpoints defined in OpenAPI/Swagger spec
   → Much more targeted than full active scan
   → Runtime: ~15-30 minutes depending on API size

3. Full Scan (nightly / pre-release):
   docker run -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
     -t http://staging.company.com \
     -r full_report.html \
     -m 10    # spider minutes
   → Full spider + active scan
   → Runtime: 1-3 hours depending on app size
   → Run as nightly job, not on every commit
```

### Handling False Positives in CI/CD

```
Create .zap/rules.tsv to suppress known false positives:
  # Rule ID  | Action  | Parameter | URL
  10021      IGNORE    *           *    # X-Content-Type-Options (handled by CDN)
  10020      IGNORE    *           *    # Anti-clickjacking (handled by CDN)

Rules file format:
  Column 1: Alert rule ID (from ZAP Alerts)
  Column 2: IGNORE (suppress) or FAIL (fail build)
  Column 3: Parameter name or * for all
  Column 4: URL pattern or * for all

Enterprise policy I implement:
  FAIL on: SQL Injection, XSS, Command Injection, Path Traversal
  IGNORE on: Missing headers when handled by WAF/CDN layer
  WARN on: Cookie issues, information disclosure (notify, don't fail)
```

---

## 🔌 ZAP API Scanning

```
ZAP's API scan mode is specifically designed for REST/GraphQL APIs
with OpenAPI, Swagger, or WSDL specifications.

Import API definition:
  Import → OpenAPI Definition from URL/File
  → Automatically creates requests for all defined endpoints
  → Populates all parameters with intelligent test values

  Or via CLI:
  zap-api-scan.py -t http://api.company.com/swagger.json -f openapi

What API scan tests:
  All endpoints defined in the spec
  All parameters with injection payloads
  HTTP method-based issues (GET vs POST for state changes)
  Authentication header handling
  Response code handling

GraphQL scanning:
  Import: send introspection query first to build schema map
  Then: right-click → Active Scan → select GraphQL policy
```

---

## 📋 How I Describe ZAP Integration in Enterprise Reports

```
Finding Title: No Automated DAST in CI/CD Pipeline

Severity: Medium (process finding)

Description:
  The application does not include automated dynamic application security
  testing (DAST) in its CI/CD pipeline. Recurring vulnerability classes
  including missing security headers and insecure cookie configurations
  could be detected and blocked at build time, before deployment to staging
  or production environments.

Recommendation:
  Integrate OWASP ZAP baseline scan into the CI/CD pipeline on every
  merge to main/develop branches. Configure the scan to fail builds when
  High severity alerts are introduced.

  Estimated implementation time: 2-4 hours (GitHub Actions template provided)
  Expected outcome: Recurring vulnerability reduction 40-50% within 2 sprints
```

---

## 🧭 Key Takeaways

**1. ZAP's highest value in enterprise is CI/CD integration, not manual testing.**
For manual testing, Burp Suite Pro is significantly more capable. ZAP's strength is being free, scriptable, Docker-packaged, and designed for automated pipeline integration. This combination makes it the standard DAST choice for DevSecOps implementation.

**2. Start with baseline scan — get it running in the pipeline in one day.**
The ZAP baseline scan Docker image runs as a single command with zero configuration. Getting it into a GitHub Actions or Jenkins pipeline takes a few hours at most. Once it is running, it catches header/cookie/obvious issues on every build automatically.

**3. API scan with OpenAPI spec is more effective than blind spidering.**
Modern enterprise APIs have OpenAPI/Swagger specs for developer documentation. Giving this spec to ZAP's API scan mode means every endpoint and parameter is automatically tested — no spidering required. The coverage is dramatically better than blind crawling.

**4. Always run in staging, never production for active scans.**
Baseline/passive scans are safe on production. Active scans with injection payloads can cause application errors, trigger rate limiting, or generate false entries in databases. The enterprise standard is: passive scan on production, active scan on an identical staging environment.

---

## 🔗 References
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [ZAP GitHub Actions](https://github.com/zaproxy/action-baseline)
- [ZAP Docker Hub](https://hub.docker.com/r/zaproxy/zaproxy)
- [OWASP DAST Guide](https://owasp.org/www-project-devsecops-guideline/)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
