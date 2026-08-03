# Enterprise Web Application Reconnaissance Workflow

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Reconnaissance Methodology — Enterprise Engagement Framework
>
> **Context:** This is my complete reconnaissance workflow for enterprise web application engagements — the systematic process I run in the first 3-4 hours of every assessment before testing a single vulnerability. Recon in enterprise testing is fundamentally different from bug bounty hunting: the scope is defined and narrow, the environment is often internal, and the goal is not to find the most interesting target but to completely map a specific, agreed application. The depth and structure of recon determines the quality of everything that follows. 

---

## 🧠 Enterprise Recon vs Bug Bounty Recon — The Key Differences

```
Bug bounty recon:
  → Scope: everything on *.target.com (wide)
  → Goal: find any vulnerability anywhere
  → Timeline: unlimited, work at your own pace
  → Environment: always external/public-facing
  → Method: automate widely, chase leads

Enterprise penetration test recon:
  → Scope: specific applications, specific IP ranges (narrow, defined)
  → Goal: completely map the attack surface of agreed targets
  → Timeline: fixed window (typically 1-5 days total engagement)
  → Environment: may include internal applications behind VPN
  → Method: structured, systematic, documented
  → Constraint: rate limiting awareness (shared/prod environments)
  → Output: recon notes that directly feed the testing matrix
```

The enterprise recon philosophy: **know the application completely before testing a single vulnerability.**

---

## 🗂️ Phase 0 — Scope Review & Target Mapping (30 minutes before any tools)

Before any tool touches the target, spend 30 minutes with the scope document.

```
Extract from scope document:
  → All in-scope domains and subdomains
  → All in-scope IP ranges and CIDR blocks
  → All in-scope applications (web app, APIs, mobile backend)
  → Explicit out-of-scope items
  → Rate limiting rules ("no automated scanning on prod")
  → Testing hours ("testing only between 09:00-17:00 IST")
  → Emergency contact for service disruption

Build your target list:
  Primary targets:  app.company.com, api.company.com
  Admin panels:     admin.company.com (if in scope)
  APIs:             api.company.com/v1, api.company.com/v2
  Staging:          staging.company.com (if in scope)
  IP ranges:        10.0.0.0/24 (internal, if VPN provided)

Rule: If it is not in the scope document, do not test it.
      If you find something interesting that is not in scope,
      report it to the client as an out-of-scope observation,
      not as a tested finding.
```

---

## 🔍 Phase 1 — Passive Reconnaissance (Zero Contact With Target)

All activities in this phase leave no trace in the target's logs. Can be done before engagement officially starts.

### 1.1 — Certificate Transparency Subdomain Mapping

```bash
# crt.sh — every SSL certificate ever issued for the domain
curl -s "https://crt.sh/?q=%.company.com&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | tr ',' '\n' \
  | sort -u \
  | tee ct_subdomains.txt

# What this finds that you would never guess:
#   dev.company.com          → dev environment (weaker controls)
#   jenkins.company.com      → CI/CD pipeline (credential goldmine)
#   confluence.company.com   → internal wiki
#   staging-api.company.com  → staging API (often no WAF)
#   backup.company.com       → backup server (default creds common)
#   vpn.company.com          → VPN portal (phishing target if in scope)
```

### 1.2 — Google Dorking

```
# Run these searches manually in browser — no tools, no target contact

# Sensitive file types indexed by Google:
site:company.com filetype:env
site:company.com filetype:sql
site:company.com filetype:log
site:company.com filetype:bak
site:company.com filetype:config
site:company.com filetype:xml "connectionString"

# Admin and login panels:
site:company.com inurl:admin
site:company.com inurl:login
site:company.com inurl:portal
site:company.com inurl:dashboard
site:company.com intitle:"Index of"

# Error messages with internal details:
site:company.com "Exception" "stack trace"
site:company.com "SQL syntax" OR "mysql_fetch_array"
site:company.com "Warning:" "on line"
site:company.com "Unhandled exception"

# API and documentation exposure:
site:company.com inurl:swagger
site:company.com inurl:api-docs
site:company.com inurl:graphql
site:company.com "api_key" OR "access_token" filetype:js

# Google result count: note how many pages are indexed
# site:company.com → shows total indexed pages
# Sudden large count suggests unintentionally indexed content
```

### 1.3 — GitHub & Source Code Intelligence

```bash
# Search GitHub for company domain in code (web interface)
Searches to run at github.com/search:

  company.com password
  company.com api_key
  company.com secret_key
  company.com DB_PASSWORD
  company.com connectionString
  "company.com" filename:.env
  "company.com" filename:web.config
  "company.com" filename:appsettings.json
  "company.com" filename:application.properties

# Automated scanning of company GitHub org:
trufflehog github --org=company-github-org --only-verified 2>/dev/null | tee trufflehog_results.txt

# gitleaks on specific repos:
gitleaks detect --source=/path/to/repo --report-format json

# What leaks are typically found:
#   Hard-coded API keys committed to feature branches
#   .env files committed before being added to .gitignore
#   Database credentials in config files in private-turned-public repos
#   JWT secrets in unit test files
#   AWS keys in deployment scripts
```

### 1.4 — Shodan & Censys Passive Mapping

```bash
# Shodan (web interface or CLI — no contact with target)
# Find all internet-facing assets for the organisation:

shodan search org:"Company Name" --fields ip_str,port,hostnames,product,version

# Specific searches on shodan.io:
# org:"Company Name" http.title:admin           → admin panels
# org:"Company Name" product:"Spring Boot"       → Java apps with Actuator
# org:"Company Name" port:8080,8443,9200,6379    → non-standard ports
# org:"Company Name" ssl.cert.subject.cn:company.com → all SSL assets

# What Shodan surfaces that surprises enterprise clients:
#   Redis instances open to internet with no authentication
#   Elasticsearch clusters with no auth (full data access)
#   Jenkins CI/CD with default credentials
#   Old application versions still running on non-standard ports
#   Docker API exposed on port 2375 (unauthenticated container access)
```

### 1.5 — DNS Intelligence

```bash
# Collect DNS records without touching the application server
dig +short A company.com                    # IPv4 addresses
dig +short AAAA company.com                 # IPv6 addresses
dig +short MX company.com                   # Mail servers → hosting intel
dig +short TXT company.com                  # SPF → cloud services used
dig +short NS company.com                   # Name servers
dig +short CNAME api.company.com            # May reveal cloud provider

# SPF record intelligence:
# v=spf1 include:_spf.google.com → uses Google Workspace
# include:amazonses.com           → uses AWS SES
# include:sendgrid.net            → uses SendGrid
# ip4:192.168.x.x                → internal IP range revealed!

# CNAME reveals hosting:
# api.company.com → CNAME → api.company.com.eu-west-1.elb.amazonaws.com
#                          → confirms AWS, region: eu-west-1

# Reverse DNS on application IP:
dig -x $(dig +short company.com)
# Reveals: other domains hosted on same IP → shared hosting intel
```

---

## 🔍 Phase 2 — Active Enumeration (Makes Contact With Target)

All activities from here onwards are logged in the target's web server, WAF, and SIEM.
Only proceed when the engagement is formally started and the SOC has been notified if required.

### 2.1 — Technology Fingerprinting (First Request)

```bash
# Collect response headers from main application
curl -sI https://app.company.com | tee headers.txt

# What headers reveal:
Server: Microsoft-IIS/8.5          → .NET stack, IIS version
X-Powered-By: ASP.NET              → confirms .NET
X-AspNet-Version: 4.0.30319        → precise .NET version
X-AspNetMvc-Version: 5.2           → MVC version
Set-Cookie: JSESSIONID=...         → Java (Tomcat/Spring)
Set-Cookie: PHPSESSID=...          → PHP
Set-Cookie: .ASPXAUTH=...          → ASP.NET Forms Auth
X-Generator: Drupal 8              → CMS version (check CVEs)

# Also check:
curl -s https://app.company.com | grep -iE 'generator|powered|framework|version'
# HTML comments sometimes reveal versions

# This fingerprint DETERMINES:
# → Which wordlists to use in directory enumeration
# → Which payload sets to use (PHP vs ASP.NET vs Java)
# → Which known CVEs to check
# → Which configuration files to look for (web.config vs .htaccess)
```

### 2.2 — Subdomain Live-Host Verification

```bash
# Passive sources gave us a list → now verify which are actually live
# Use httpx for fast parallel probing:

cat ct_subdomains.txt | httpx \
  -sc \
  -title \
  -server \
  -tech-detect \
  -o live_subdomains.txt

# Output format: URL | Status | Title | Server | Technologies
# Example:
# https://jenkins.company.com [200] [Jenkins] [Apache Tomcat] [Java]
# https://staging-api.company.com [200] [Staging API v2.1] [IIS]
# https://backup.company.com [403] [] [Nginx]  ← investigate 403s!
# https://old-portal.company.com [302] → points somewhere else

# Prioritise by:
# 1. Status 200 + "admin" or "login" in title → immediate manual review
# 2. Status 403 → investigate bypass techniques
# 3. Status 401 → attempt default credentials
# 4. Technology: "Spring Boot" → check /actuator immediately
```

### 2.3 — Application Mapping With Burp Suite

```bash
# Configure Burp before this step:
# - Scope set to in-scope domains only
# - Proxy intercept ON
# - All extensions loaded (Autorize, JS Miner, Param Miner)
# - Collaborator client open

# Manual application walkthrough (most important recon step):
# Browse the entire application as each user role:
#   → Unauthenticated: note what is accessible without login
#   → Standard user: map all features and API calls
#   → Admin user (if test account provided): map admin functionality

# While browsing, note in your recon log:
#   → All URL patterns and API endpoint structures
#   → Authentication mechanism (cookie? JWT? Basic Auth?)
#   → Session token format (Base64? JWT? Random?)
#   → All file upload features
#   → All URL-fetching features (webhooks, image import, PDF gen)
#   → All ID patterns (sequential int? UUID? custom format?)
#   → All admin vs user functionality boundaries

# JS Miner runs automatically → review extracted endpoints
# Document: every API endpoint found in JS bundles
```

### 2.4 — Directory & Content Enumeration

```bash
# Step 1: robots.txt and sitemap (always first)
curl -s https://app.company.com/robots.txt
curl -s https://app.company.com/sitemap.xml

# Step 2: Quick initial scan (2-3 minutes, highest-value paths)
gobuster dir \
  -u https://app.company.com \
  -w /opt/SecLists/Discovery/Web-Content/common.txt \
  -b 404,400 \
  -t 20 \
  -q \
  -o gobuster_quick.txt

# Step 3: Technology-specific scan (based on fingerprinting from 2.1)
# ASP.NET/IIS:
gobuster dir \
  -u https://app.company.com \
  -w /opt/SecLists/Discovery/Web-Content/IIS.fuzz.txt \
  -x asp,aspx,config,bak \
  -t 15 \
  -o gobuster_iis.txt

# Java/Spring Boot:
# Check immediately (before full scan — highest value):
for path in actuator actuator/env actuator/heapdump swagger-ui.html \
            swagger-ui/index.html v2/api-docs graphql h2-console console; do
  code=$(curl -so /dev/null -w "%{http_code}" https://app.company.com/$path)
  echo "$code  /$path"
done

# Step 4: API endpoint enumeration
gobuster dir \
  -u https://app.company.com/api \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
  -t 15 \
  -o gobuster_api.txt

# Step 5: Full scan (runs in background during manual testing)
feroxbuster \
  -u https://app.company.com \
  -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -d 2 \
  --filter-status 404,400,500 \
  -o feroxbuster_full.txt \
  --quiet
```

### 2.5 — API Specification Discovery

```bash
# Check for Swagger / OpenAPI specs:
for path in swagger swagger-ui swagger-ui.html swagger-ui/index.html \
            api/swagger-ui.html v2/api-docs v3/api-docs openapi.json \
            openapi.yaml api/openapi.json api-docs docs api/docs; do
  code=$(curl -so /dev/null -w "%{http_code}" https://app.company.com/$path)
  [[ "$code" == "200" ]] && echo "FOUND: /$path [$code]"
done

# Check for GraphQL introspection:
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' \
  | jq '.data.__schema.types[].name' 2>/dev/null | head -20

# If GraphQL responds with types → introspection enabled → full schema available
# Download full schema for analysis
```

### 2.6 — Wayback Machine Historical URL Extraction

```bash
# Find old endpoints that still exist but are no longer linked:
curl -s "https://web.archive.org/cdx/search/cdx?\
url=*.company.com/*&output=json&fl=original&collapse=urlkey&limit=5000" \
  | jq -r '.[][0]' \
  | sort -u \
  | tee wayback_urls.txt

# Filter for interesting historical paths:
grep -iE "(admin|api|backup|config|debug|test|dev|internal|swagger|\.env|\.sql|\.bak)" \
  wayback_urls.txt | tee wayback_interesting.txt

# Probe which historical URLs still respond:
cat wayback_interesting.txt | httpx -sc -o wayback_live.txt
```

---

## 📊 Phase 3 — Recon Output Analysis & Testing Prioritisation

After running all recon, consolidate findings into a prioritised testing matrix before writing a single attack payload.

```
Recon Analysis Checklist:

IMMEDIATE HIGH-PRIORITY TARGETS (test in first hour):
  □ Spring Boot Actuator found → /actuator/env (credentials likely)
  □ Admin panel found with 200 status → default credentials
  □ .env or web.config found with 200 → read content
  □ .git/ found with 200 → run gitdumper for source code
  □ Swagger/OpenAPI spec found → import to Postman
  □ GraphQL introspection enabled → download full schema

HIGH-PRIORITY (test second):
  □ Staging/dev subdomains identified → test for weaker controls
  □ GitHub leaks found → credential stuffing on auth endpoints
  □ Old API versions found (v1 when v2 is current) → test for missing auth
  □ Non-standard ports identified (8080, 8443, 9200) → direct API access
  □ All 403 responses from directory enumeration → bypass testing

STANDARD TESTING QUEUE (systematic coverage):
  □ All identified input parameters (injection testing)
  □ All API endpoints (IDOR, auth bypass, mass assignment)
  □ All file upload features
  □ All URL-fetching features (SSRF)
  □ All authentication flows (session, JWT, OAuth)

BUILD TESTING MATRIX:
  Endpoint | Method | Auth Required | ID Parameters | Priority
  /api/v1/users/{id} | GET | Yes | user_id | High (IDOR)
  /api/v1/reports?ref={id} | GET | Yes | ref | High (SQLi + IDOR)
  /admin/users | GET | No | - | CRITICAL (unauth admin)
  /api/webhooks | POST | Yes | url param | High (SSRF)
```

---

## 📋 Recon Notes Template — What I Document

```markdown
## Engagement: [Client Name] — [Application Name]
## Date: [DD-MM-YYYY]
## Tester: Dheeraj Kumar Jayaswal

### Target Inventory
  Primary: https://app.company.com
  API: https://api.company.com
  Admin: https://admin.company.com

### Technology Stack
  Backend: ASP.NET Core 6.0 (X-Powered-By header)
  Database: SQL Server (error message leak)
  Auth: JWT (Bearer token in Authorization header)
  Hosting: AWS (CNAME → elb.amazonaws.com)
  WAF: Cloudflare (CF-Ray header)

### Subdomain Inventory (Live)
  https://app.company.com          [200] Main application
  https://api.company.com          [200] API backend
  https://admin.company.com        [403] Admin panel ← investigate
  https://staging.company.com      [200] Staging ← test separately
  https://jenkins.company.com      [200] Jenkins ← credential test

### Interesting Paths Found
  /actuator/env                    [403] ← try bypass
  /swagger-ui.html                 [200] ← FOUND API docs
  /api/v1/ (old)                   [200] ← test vs /api/v2/
  /.git/HEAD                       [404] ← not exposed
  /web.config                      [404] ← not exposed

### GitHub Findings
  No leaked credentials found for company.com

### Attack Surface Summary
  Authentication: JWT, login at /api/auth/login
  Session: Bearer token in Authorization header
  Object IDs: Sequential integers (/api/users/1042)
  File uploads: /api/documents/upload (PDF, DOCX)
  URL fetching: /api/webhooks (POST with url parameter) ← SSRF candidate
  Admin functions: /admin/* (403, investigate bypass)
  Swagger spec: /swagger-ui.html ← import to Postman

### Priority Testing Queue
  1. SSRF: /api/webhooks url parameter
  2. IDOR: /api/users/{id}, /api/invoices/{id}
  3. JWT: alg:none, weak secret test
  4. API v1: test /api/v1/ endpoints for missing auth vs /api/v2/
  5. Admin bypass: test /admin/ with X-Original-URL header
  6. Injection: /api/reports?ref= (reflective parameter)
```

---

## 🤖 Recon Automation Script (Enterprise Version)

```bash
#!/bin/bash
# Enterprise recon script — Dheeraj Kumar Jayaswal
# Usage: ./enterprise_recon.sh company.com
# Requires: subfinder, httpx, gobuster, feroxbuster, curl, jq

TARGET=$1
OUTPUT_DIR="recon_${TARGET}_$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

echo "════════════════════════════════════════"
echo "  Enterprise Recon — $TARGET"
echo "  Started: $(date)"
echo "════════════════════════════════════════"

# Phase 1: Passive subdomain enumeration
echo "[1/6] Certificate Transparency..."
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//g' | tr ',' '\n' | sort -u \
  > "$OUTPUT_DIR/ct_subdomains.txt"

echo "[2/6] Subfinder passive..."
subfinder -d "$TARGET" -silent \
  >> "$OUTPUT_DIR/ct_subdomains.txt" 2>/dev/null
sort -u "$OUTPUT_DIR/ct_subdomains.txt" -o "$OUTPUT_DIR/all_subdomains.txt"
echo "       Found: $(wc -l < $OUTPUT_DIR/all_subdomains.txt) subdomains"

# Phase 2: Live host detection
echo "[3/6] Probing live hosts..."
cat "$OUTPUT_DIR/all_subdomains.txt" | httpx \
  -silent -sc -title -server \
  -o "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null
echo "       Live: $(wc -l < $OUTPUT_DIR/live_hosts.txt) hosts"

# Phase 3: DNS records
echo "[4/6] DNS records..."
{
  echo "=== A Records ===" && dig +short A "$TARGET"
  echo "=== MX Records ===" && dig +short MX "$TARGET"
  echo "=== TXT/SPF ===" && dig +short TXT "$TARGET"
  echo "=== CNAME ===" && dig +short CNAME "www.$TARGET"
} > "$OUTPUT_DIR/dns_records.txt"

# Phase 4: High-value path check (quick, most important)
echo "[5/6] High-value path check..."
PATHS=(
  "actuator" "actuator/env" "actuator/heapdump" "actuator/mappings"
  "swagger-ui.html" "swagger-ui/index.html" "v2/api-docs" "openapi.json"
  ".env" ".git/config" "web.config" "phpinfo.php"
  "admin" "admin/" "administrator" "phpmyadmin"
  "graphql" "console" "h2-console" "server-status"
)
{
  echo "=== High-Value Path Scan: https://$TARGET ==="
  for path in "${PATHS[@]}"; do
    code=$(curl -so /dev/null -w "%{http_code}" \
           --max-time 5 "https://$TARGET/$path" 2>/dev/null)
    [[ "$code" =~ ^(200|301|302|401|403)$ ]] && echo "$code  /$path"
  done
} > "$OUTPUT_DIR/highvalue_paths.txt"
grep "^200" "$OUTPUT_DIR/highvalue_paths.txt" | while read line; do
  echo "       *** FOUND 200: $line"
done

# Phase 5: Directory enumeration (background)
echo "[6/6] Starting background directory enum..."
gobuster dir \
  -u "https://$TARGET" \
  -w /opt/SecLists/Discovery/Web-Content/common.txt \
  -b 404,400 -t 20 -q \
  -o "$OUTPUT_DIR/gobuster_common.txt" 2>/dev/null &

echo ""
echo "════════════════════════════════════════"
echo "  Recon Complete — $(date)"
echo "  Output directory: $OUTPUT_DIR/"
echo ""
echo "  Files:"
ls "$OUTPUT_DIR/"
echo ""
echo "  NEXT STEPS:"
echo "  1. Review live_hosts.txt — identify staging/dev/admin targets"
echo "  2. Review highvalue_paths.txt — investigate any 200 responses"
echo "  3. Check gobuster_common.txt when background scan finishes"
echo "  4. Start manual Burp browsing of primary target"
echo "════════════════════════════════════════"
```

---

## 🗂️ Recon Completion Checklist

```
PASSIVE (complete before any active testing):
  ☐ Certificate transparency subdomain list generated
  ☐ Google dorking completed (sensitive files, admin panels, errors)
  ☐ GitHub searched for domain + credential keywords
  ☐ Shodan/Censys queried for organisation assets
  ☐ DNS records collected (A, MX, TXT, CNAME, NS)
  ☐ Wayback Machine historical URL extraction

ACTIVE (systematic, logged in target):
  ☐ Response headers collected → technology stack documented
  ☐ All subdomains probed for live status + titles
  ☐ robots.txt and sitemap.xml reviewed
  ☐ High-value paths checked: Actuator, Swagger, .env, .git
  ☐ Directory enumeration running (common.txt + tech-specific)
  ☐ Application manually browsed as each user role in Burp
  ☐ API specification discovered (Swagger/OpenAPI/GraphQL)
  ☐ Wayback URLs probed for live responses

ANALYSIS (before testing begins):
  ☐ Recon notes documented in standard format
  ☐ Technology stack confirmed
  ☐ Testing priority matrix built
  ☐ Burp scope configured (in-scope domains only)
  ☐ Autorize configured with victim user session
  ☐ Collaborator client running
  ☐ First priority: any 200 responses on high-value paths
```

---

## 🧭 Key Takeaways From 5+ Years of Enterprise Testing

**1. Passive recon before active recon — always.**
Passive sources (crt.sh, GitHub, Shodan, Google) leave no trace and often surface the most impactful findings. Multiple Critical findings in my career were discovered passively — credentials in GitHub commits, exposed Jenkins servers in certificate transparency, S3 bucket names in JS bundles. Start here before touching the target.

**2. Certificate transparency is the single best subdomain source.**
It is passive, comprehensive, and finds subdomains that DNS brute forcing misses — because it captures every domain that has ever received an SSL certificate. A Jenkins CI/CD server that was internal three years ago and then accidentally given a public certificate and internet access is not in any subdomain brute force wordlist. It is in crt.sh.

**3. The technology stack fingerprint determines everything downstream.**
Knowing that the application is ASP.NET on IIS before directory enumeration means you use the IIS wordlist, look for web.config, target ELMAH and trace.axd, and check for .NET-specific deserialization in cookies. Getting the technology wrong wastes hours with the wrong tools.

**4. The recon notes ARE the engagement plan.**
When recon is complete, the testing matrix is already built. Each high-value path found, each URL-fetching feature identified, each object ID pattern observed — these become the testing queue. An engagement with complete recon notes is an engagement that can be handed to any tester and executed consistently. An engagement without them is improvisation.

**5. Document what you did NOT find as well as what you found.**
A professional report notes that /.git/ returned 404, that no GitHub leaks were found, that Spring Actuator was inaccessible. This demonstrates to the client that coverage was thorough — the absence of a finding was confirmed, not overlooked. Negative findings are as important as positive ones in an enterprise engagement context.

---

## 🔗 References
- [OWASP Testing Guide — Information Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [crt.sh Certificate Transparency](https://crt.sh)
- [Subfinder GitHub](https://github.com/projectdiscovery/subfinder)
- [httpx GitHub](https://github.com/projectdiscovery/httpx)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [Shodan](https://www.shodan.io)

---

<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
