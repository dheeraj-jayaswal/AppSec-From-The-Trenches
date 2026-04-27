# Sensitive Data Exposure — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Cryptographic Failures & Data Exposure — OWASP A02:2021
>
> **Severity:** High to Critical — data breach, credential theft, regulatory violations (GDPR, PCI-DSS, HIPAA)
>
> **Real-world impact:** Sensitive data exposure is the finding I document most frequently in enterprise engagements — not because it is the hardest to exploit, but because it is the most widespread. Developers solve functional problems first and secure data handling second. The result is a consistent stream of PII, credentials, API keys, and internal system details leaking through paths nobody thought to lock down.

---

## 🧠 Why This Write-Up Exists

Sensitive data exposure rarely requires a sophisticated attack. You do not need to chain exploits or bypass security controls. You need to look in places that developers forgot to think about — the JavaScript bundle that went to production with debug keys still in it, the API response that returns 47 fields when the UI only displays 6, the `.env` file that was committed to a git repository 18 months ago and nobody noticed.

In five years of enterprise penetration testing, I have found credentials in JavaScript source maps, PII in API responses that the frontend never rendered, AWS keys in mobile app bundles, full stack traces leaking database schemas in production error pages, and backup `.sql` files sitting in the web root.

This document covers how to systematically find all of it.

---

## 📖 What Is Sensitive Data Exposure?

Sensitive data exposure occurs when an application fails to adequately protect information — either **in transit** (over the network), **at rest** (in storage), or **in use** (in code, logs, error messages, or API responses).

The OWASP 2021 update renamed this category "Cryptographic Failures" to emphasise the root cause — failures in encryption, key management, and data classification — but the practical attack surface remains the same.

```
Enterprise Sensitive Data Exposure Attack Surface:

  [Transport Layer]     → HTTP without TLS, weak TLS config, missing HSTS
  [API Responses]       → Over-fetching, hidden fields, unauthenticated endpoints
  [Error Messages]      → Stack traces, SQL errors, file paths, versions, internal IPs
  [Source Code / JS]    → Hardcoded secrets, API keys in frontend bundles, source maps
  [Exposed Files]       → .env, backup files, config files, git repositories, log files
  [URL Parameters]      → Tokens, credentials, PII in GET requests
  [Cookies & Headers]   → Missing Secure/HttpOnly flags, sensitive data in headers
  [Logs & Caches]       → Sensitive data written to accessible log paths or CDN caches
  [Third-Party Scripts] → External JS with access to page data (Magecart-style)
```

---

## 🔍 Phase 1 — Reconnaissance: Mapping the Data Exposure Surface

Before running any tools, spend time passively observing what the application reveals during normal usage. The highest-value findings often require no special technique — just careful observation.

### What to Watch in Burp Suite During Normal Browsing

Set Burp to intercept and use the application as a real user for 20–30 minutes. While doing so, watch for:

```
In HTTP History — flag anything that contains:

Response body:
  password, passwd, pwd, secret, api_key, token, access_key
  ssn, national_id, pan, card_number, cvv, dob, account_number
  internal_ip, server_name, db_name, table_name, stack_trace
  Exception, StackTrace, System.NullReferenceException
  /var/www, /home/, C:\inetpub, C:\Windows

Request URLs:
  ?token=, ?key=, ?password=, ?secret=, ?email=
  ?ssn=, ?card=, ?dob=

Response headers:
  X-Powered-By: ASP.NET 4.7       ← version disclosure
  Server: Microsoft-IIS/8.5       ← version disclosure
  X-AspNet-Version: 4.0.30319     ← internal version info
```

**Burp Suite tip:** Use the Search function (Ctrl+F in HTTP History) to search across all captured responses for the strings above. This finds leakage in responses you might scroll past manually.

---

## 💥 Phase 2 — Attack Vectors

### Vector 1 — Sensitive Data in API Responses (Over-Fetching)

This is the most consistently productive finding in enterprise application testing. Modern applications built on microservices and REST/GraphQL APIs frequently return far more data than the frontend renders. Developers return entire object models from the backend and let the frontend filter what to display — but the raw API response goes to the browser.

**How to test in Burp Suite:**

```
Step 1: Open the application, perform standard actions
        (view profile, list records, search, export)

Step 2: In Burp HTTP History, find API calls:
        GET /api/v1/users/profile
        GET /api/v1/employees/search?q=john
        GET /api/v2/orders/12345

Step 3: Send each to Repeater, resend, examine FULL response body

Step 4: Compare raw JSON response against what the UI actually displays

Common hidden fields found in enterprise API responses:
{
  "id": 1042,
  "name": "John Smith",           ← displayed in UI
  "email": "john@company.com",    ← displayed in UI
  "password_hash": "$2a$10$...",  ← NOT displayed — but present in response!
  "ssn": "XXX-XX-6789",           ← masked in UI — full value in API!
  "date_of_birth": "1985-04-12",  ← not shown — but in response
  "salary": 95000,                ← not shown — but in response
  "is_admin": false,              ← privilege field — never shown
  "internal_notes": "VIP client", ← internal data leaking to all users
  "api_key": "live_sk_abc123xyz"  ← secret key returned to browser!
}
```

**Test unauthenticated access to API endpoints:**

```
Take any authenticated API endpoint from Burp History:
GET /api/v1/users/profile HTTP/1.1
Authorization: Bearer eyJhbG...

Send to Repeater → Remove the Authorization header entirely → Send

If you receive data = Unauthenticated API endpoint
If you receive a 200 but different data = Information disclosure on auth failure
```

**Test for IDOR in data exposure (combined finding):**

```
GET /api/v1/users/1042   → your profile data
GET /api/v1/users/1041   → another user's profile data

If both return full PII = IDOR + Sensitive Data Exposure combined finding
Severity escalates to Critical
```

> **Enterprise context:** In one engagement, a healthcare application returned patient date-of-birth, full address, and insurance policy numbers in the profile API endpoint. The frontend only displayed name and email. A developer had returned the full Patient object from the database without a DTO (Data Transfer Object) mapping — a classic enterprise pattern failure. 3,200 patient records were accessible to any authenticated user via sequential ID enumeration.

---

### Vector 2 — Verbose Error Messages & Stack Traces

Enterprise applications — particularly those built on .NET, Java Spring, and PHP Laravel — produce rich error messages in development mode. These are frequently left enabled in production, especially on internal-facing applications.

**Payloads to trigger informative errors:**

```
Send these values to every input parameter and observe responses:

Type confusion:
  numeric fields  → send "abc", "null", "undefined", "true", "'", "[]"
  string fields   → send 99999999, -1, 0
  ID parameters   → send 0, -1, null, 99999999, "' OR 1=1--"

Boundary testing:
  Send empty string: param=
  Send very long input: param=AAAA...(5000 chars)
  Send null bytes: param=%00
  Send Unicode: param=\u0000

Non-existent resources:
  /api/v1/users/99999999
  /api/v1/orders/INVALID-UUID-FORMAT
  /admin/nonexistent-page
```

**What information leaks look like in enterprise .NET apps:**

```
HTTP/1.1 500 Internal Server Error

{
  "Message": "An error has occurred.",
  "ExceptionMessage": "The column name 'UserID' is not valid.",
  "ExceptionType": "System.Data.SqlClient.SqlException",
  "StackTrace": "   at System.Data.SqlClient.SqlConnection.OnError...
    at CompanyApp.DataLayer.UserRepository.GetUserById(Int32 id)
    at CompanyApp.BusinessLayer.UserService.FetchProfile(Int32 userId)
    at CompanyApp.Controllers.UserController.GetProfile(Int32 id)
    in C:\\inetpub\\wwwroot\\CompanyApp\\Controllers\\UserController.cs:line 47"
}

Information disclosed:
→ Database column names (attack SQLi with precision)
→ Internal class names and architecture (UserRepository, UserService)
→ Physical file path: C:\inetpub\wwwroot\CompanyApp\
→ Framework: System.Data.SqlClient (SQL Server)
→ Exact line number of vulnerable code
```

**Version disclosure in response headers:**

```
In Burp Suite — inspect response headers on any page:

Server: Microsoft-IIS/8.5          → IIS version (check CVE database)
X-Powered-By: ASP.NET              → confirm .NET stack
X-AspNet-Version: 4.0.30319        → exact .NET version
X-AspNetMvc-Version: 5.2           → MVC version
X-Generator: Drupal 7              → CMS with known CVEs
```

> **Enterprise context:** A financial services internal portal returned a full ASP.NET stack trace on any invalid integer ID, including the full file path `C:\inetpub\wwwroot\FinancePortal\` and SQL Server table and column names. This gave me the exact column structure I needed to craft precise SQL injection payloads in the same engagement.

---

### Vector 3 — JavaScript Source Code & Bundle Analysis

Modern enterprise applications compile frontend code into minified JavaScript bundles. These bundles frequently contain hardcoded API keys, internal endpoint paths, environment-specific configuration, and comments left by developers.

**Finding and analysing JavaScript files:**

```
In Burp Suite → HTTP History → filter by .js extension

Or in browser DevTools:
1. Open DevTools → Sources tab
2. Look for: main.chunk.js, app.bundle.js, vendor.js, config.js
3. Use Pretty Print button ({}) to make minified code readable
4. Ctrl+F to search for: key, secret, password, token, api, aws, config
```

**JavaScript Source Map Exposure (.js.map files):**

This is one of the most underappreciated findings in enterprise web application testing. Source maps are generated during build to help developers debug minified code — they contain the full original source code. When deployed to production accidentally, they expose the entire frontend codebase.

```
Test for source map exposure:

If you find: https://app.company.com/static/js/main.abc123.js
Test:        https://app.company.com/static/js/main.abc123.js.map

If the .map file returns a 200 response:
- Download it
- Open in browser or text editor
- Contains: full original source code, comments, variable names,
  internal API endpoint paths, developer notes, and often credentials

Source map contains a "sources" array with original file paths:
{
  "sources": [
    "src/config/apiKeys.js",      ← look at this file
    "src/services/authService.js",
    "src/utils/database.js"
  ],
  "sourcesContent": ["const API_KEY = 'live_sk_abc123...'..."]
}
```

**Common hardcoded secrets to look for in JS bundles:**

```
Patterns to search in Burp or DevTools:

Cloud credentials:
  AKIA                    → AWS Access Key ID prefix
  aws_secret_access_key
  azure_client_secret
  GOOGLE_APPLICATION_CREDENTIALS

API keys:
  api_key, apiKey, api_secret
  stripe_secret, STRIPE_KEY
  sendgrid_api_key
  twilio_auth_token

Auth secrets:
  jwt_secret, JWT_SECRET
  client_secret
  encryption_key

Internal endpoints:
  /internal/, /admin/, /api/v2/private/
  192.168., 10.0., 172.16.      ← internal IP ranges
```

> **Enterprise context:** In a retail sector engagement, I found an exposed `.js.map` file on the production CDN. The source map contained the full original React source code including a `config.js` file with a Stripe live secret key, a SendGrid API key, and five internal API endpoint paths that were not linked from the UI. The build pipeline had a step that deployed source maps to production — no developer had questioned it because the files had no obvious impact on functionality.

---

### Vector 4 — Exposed Files, Directories & Git Repositories

**High-value paths to test in enterprise environments:**

```
Configuration files:
/web.config                    ← ASP.NET configuration (connection strings!)
/appsettings.json              ← .NET Core secrets
/appsettings.Production.json
/appsettings.Development.json  ← dev config sometimes in production
/App_Data/                     ← ASP.NET data directory
/global.asax
/packages.config               ← reveals framework versions

Environment files:
/.env
/.env.production
/.env.local
/.env.backup

Database files:
/backup.sql
/database.sql
/db_backup.zip
/dump.sql
/export.csv

Log files:
/logs/
/log/
/error.log
/access.log
/debug.log
/application.log
/App_Data/logs/

Git repository:
/.git/config              ← confirms git repo, may show remote URL
/.git/HEAD
/.git/COMMIT_EDITMSG      ← last commit message
/.git/logs/HEAD           ← commit history
```

**Testing with Burp Suite Intruder:**

```
1. Capture any request → Send to Intruder
2. Set target URL to: https://target.com/§FUZZ§
3. Payload: use a sensitive files wordlist
   (SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt)
4. Run → filter results for 200, 301, 302 responses
5. Investigate every non-404 response

In Burp Pro: use Active Scanner with path traversal and file discovery checks
```

**Robots.txt and sitemap as recon sources:**

```
Always check first:
/robots.txt     → Disallowed paths are often the most interesting ones
/sitemap.xml    → Full URL map of the application

Common goldmine entries in enterprise robots.txt:
Disallow: /admin/
Disallow: /internal/
Disallow: /api/v2/private/
Disallow: /backup/
Disallow: /staging/
```

> **Enterprise context:** On an internal enterprise portal engagement, I found an exposed `web.config` file containing a SQL Server connection string with credentials: `Server=PROD-DB01;Database=HRPortal;User Id=sa;Password=Company@2019`. The `sa` (system administrator) account gave full control of the SQL Server instance. This single file in the web root — left there by a developer during a migration — was the highest-severity finding of the entire engagement.

---

### Vector 5 — Sensitive Data in Transit

**Testing transport layer security:**

```
Test HTTP to HTTPS upgrade:
Navigate to: http://target.com/login
Expected: Immediate 301/302 redirect to https://
Vulnerable if: Login form served over plain HTTP OR
               HTTP version accessible with no redirect

Check HSTS (HTTP Strict Transport Security):
In Burp — look for response header:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Missing = browser may downgrade connection on future visits

Test mixed content:
On HTTPS pages, look in browser DevTools → Console for:
"Mixed Content: The page was loaded over HTTPS, but requested an insecure resource"
Mixed content = HTTP sub-resources on HTTPS pages = interception risk

Check cookie Secure flag:
In Burp HTTP History → find Set-Cookie headers on login response:
Set-Cookie: session=abc123                          ← no Secure flag!
Set-Cookie: session=abc123; Secure; HttpOnly        ← correct

Missing Secure flag = session cookie sent over HTTP connections too
```

**TLS configuration review:**

```
Test via SSL Labs (external apps):
https://www.ssllabs.com/ssltest/analyze.html?d=target.com

What to look for:
- TLS 1.0 or 1.1 still enabled → deprecated, known vulnerabilities
- RC4, DES, 3DES cipher suites → weak encryption
- BEAST, POODLE, HEARTBLEED vulnerability flags
- Certificate validity and chain issues
- Missing HSTS header

In Nmap (internal apps):
nmap --script ssl-enum-ciphers -p 443 target.internal.com
```

---

### Vector 6 — Sensitive Data in URLs and Logs

**Finding PII and credentials in URL parameters:**

```
In Burp HTTP History — look for GET requests with sensitive parameters:

Red flags in URLs:
/api/users?email=john@company.com&ssn=XXX-XX-6789
/auth/reset?token=eyJhbGc...&user=admin@company.com
/export/report?api_key=live_sk_abc&format=csv
/search?query=john&password_hint=birthdate

Why URLs are dangerous storage for sensitive data:
1. Stored in browser history (available to other users of shared computers)
2. Logged in full in web server access logs (IIS, nginx, Apache)
3. Sent as Referer header when users click external links
4. Captured by network monitoring, proxies, and SIEM systems
5. Visible in browser URL bar — shoulder surfing risk

Test:
After performing password reset, export, or auth flows —
check Burp HTTP History for GET requests with sensitive values in URL params.
```

---

## 🗂️ Phase 3 — Systematic Testing Checklist

```
API RESPONSES
☐ Compare UI display vs full raw API JSON response
☐ Look for hidden fields: password_hash, ssn, salary, api_key, is_admin
☐ Remove Authorization header — do endpoints still return data?
☐ Test sequential IDs on data endpoints (IDOR + exposure chain)
☐ Test export endpoints — CSV/PDF exports often return more than UI

ERROR MESSAGES
☐ Send invalid types to all input fields — watch for stack traces
☐ Test non-existent IDs (99999999, -1, null, 0)
☐ Send oversized inputs — may trigger different error codepath
☐ Check response headers for version disclosure (X-Powered-By, Server)
☐ Test 404 and 403 pages for framework/path disclosure

JAVASCRIPT & SOURCE MAPS
☐ Find all .js bundle files via Burp HTTP History
☐ Test each .js file for a matching .js.map file
☐ Search JS files for: AKIA, api_key, secret, jwt_secret, password
☐ Check DevTools Sources for readable config/environment files

EXPOSED FILES & DIRECTORIES
☐ Test /.env, /web.config, /appsettings.json
☐ Test /.git/config — confirms git exposure
☐ Test /robots.txt and /sitemap.xml — map interesting paths
☐ Fuzz with Burp Intruder using sensitive files wordlist
☐ Test backup extensions: .bak, .old, .backup, .zip, .sql on known files

TRANSPORT SECURITY
☐ Test HTTP login page — does it redirect to HTTPS immediately?
☐ Check session cookie for Secure and HttpOnly flags
☐ Check for HSTS header on HTTPS responses
☐ Test mixed content on HTTPS pages
☐ Check for TLS 1.0/1.1 still enabled (SSL Labs or nmap)

URLS AND LOGS
☐ Look for tokens, PII, or credentials in GET request parameters
☐ Check Referer header on external links — does it include sensitive URLs?
☐ Check if reset tokens, export keys, or session tokens appear in URLs
```

---

## 📋 Enterprise Pentest Report Template

---

**Finding Title:** Sensitive PII and Password Hash Exposed in User Profile API Response

**Severity:** High

**CVSS v3.1 Score:** 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Affected Endpoint:** `GET /api/v1/users/{id}/profile`

**Authentication Required:** Yes — Standard user session

---

**Vulnerability Description:**

The user profile API endpoint returns a full database object including fields that are not rendered in the UI and should not be accessible to authenticated users. Specifically, the response includes bcrypt password hashes, full date of birth, national ID numbers, and salary information for every user record. Additionally, the endpoint is vulnerable to IDOR — any authenticated user can retrieve the profile data of any other user by modifying the `{id}` parameter.

The root cause is the absence of a Data Transfer Object (DTO) mapping layer. The API returns the raw database entity directly, exposing all persisted fields regardless of intended visibility.

---

**Steps to Reproduce:**

1. Authenticate to the application with a standard user account
2. Navigate to the user profile page and capture the API request in Burp Suite:
   `GET /api/v1/users/1042/profile`
3. Send the request to Repeater and review the full JSON response body
4. Observe the following fields present in the response but not displayed in the UI:
   `password_hash`, `date_of_birth`, `national_id`, `salary`, `is_admin`
5. Modify the `id` value from `1042` to `1041` and resend
6. Observe another user's full profile data returned — IDOR confirmed

---

**Proof of Concept:**

```
Request:
GET /api/v1/users/1041/profile HTTP/1.1
Host: enterprise-app.company.com
Authorization: Bearer <standard_user_token>

Response:
HTTP/1.1 200 OK
{
  "id": 1041,
  "name": "Jane Doe",
  "email": "jane.doe@company.com",
  "password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
  "date_of_birth": "1988-07-23",
  "national_id": "XXXX-XXXX-7823",
  "salary": 88000,
  "is_admin": false,
  "internal_notes": "Performance review pending Q3"
}
```

---

**Business Impact:**

- Exposure of password hashes for all user accounts — offline cracking risk
- PII breach (date of birth, national ID, salary) — GDPR / regulatory violation
- Complete financial compensation data accessible to all authenticated users
- `is_admin` field accessible — informs privilege escalation targeting
- Combined with IDOR: entire user database accessible to any authenticated attacker

---

**Remediation:**

| Priority | Action |
|---|---|
| Immediate | Implement DTO mapping — return only fields the UI requires |
| Immediate | Fix IDOR — validate that `id` parameter matches the authenticated user's session |
| Short-term | Audit all API endpoints for over-fetching using automated response comparison |
| Short-term | Apply principle of least privilege to API response design |
| Long-term | Add SAST rule to flag direct entity serialisation in API controllers |
| Long-term | Introduce API contract testing in CI/CD to detect response field changes |

---

**Secure Code Pattern (C# / ASP.NET Core):**

```csharp
// ❌ VULNERABLE — returning full database entity
[HttpGet("{id}/profile")]
public async Task<IActionResult> GetProfile(int id)
{
    var user = await _userRepository.GetByIdAsync(id);
    return Ok(user); // ← returns ALL fields including password_hash, salary, ssn
}

// ✅ SECURE — DTO mapping + ownership check
[HttpGet("{id}/profile")]
public async Task<IActionResult> GetProfile(int id)
{
    // Validate the requesting user owns this resource
    var requestingUserId = int.Parse(User.FindFirst("sub")?.Value);
    if (id != requestingUserId && !User.IsInRole("Admin"))
        return Forbid();

    var user = await _userRepository.GetByIdAsync(id);
    if (user == null) return NotFound();

    // Map to DTO — only expose intended fields
    var dto = new UserProfileDto
    {
        Id       = user.Id,
        Name     = user.Name,
        Email    = user.Email
        // password_hash, ssn, salary, is_admin → NOT included
    };

    return Ok(dto);
}
```

---

## 🧪 Practice Labs

| Platform | Resource | Focus Area |
|---|---|---|
| [PortSwigger Information Disclosure Labs](https://portswigger.net/web-security/information-disclosure) | 5 free labs | Error messages, source disclosure, version leakage |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | API testing labs | Over-fetching and API data exposure |
| [HackTheBox](https://hackthebox.com) | JS analysis challenges | Source map and bundle analysis |
| [TryHackMe](https://tryhackme.com) | OWASP Top 10 rooms | Data exposure scenarios |
| [DVWA](https://github.com/digininja/DVWA) | Sensitive data module | Local safe practice environment |

---

## 🧭 Key Takeaways From 5+ Years of Enterprise Testing

**1. API responses are the biggest source of data exposure in enterprise apps.**
Developers build rich domain models in the backend and serialise them directly into API responses without thinking about what should and should not be visible. Always compare what the UI shows against what the raw JSON response contains. The gap is where the finding lives.

**2. Source maps are deployed to production more often than you think.**
Enterprise build pipelines are complex. Source maps that exist for debugging often get included in production deployments accidentally. One `.js.map` file can hand you the entire frontend codebase, hardcoded keys, and internal endpoint paths. Always test for them.

**3. Internal-facing applications are the worst offenders.**
The external-facing application gets penetration tested, reviewed, and hardened. The internal HR portal, the finance reporting tool, the admin panel — these are built by the same developers but never see a security review. Verbose errors, missing authentication, and PII over-exposure are dramatically more common in internal apps.

**4. Data exposure findings have the highest regulatory impact.**
A SQLi finding is technically severe. A finding that demonstrates 50,000 employee records are accessible without authentication is what gets immediate escalation to the CISO and triggers regulatory notification requirements. Data exposure findings move organisations the fastest.

**5. Chain your findings for maximum impact.**
Data exposure on its own is high severity. Data exposure + IDOR = critical, because now the exposed data is accessible for every user, not just your own. Always ask: does this exposure apply only to my own data, or can I access anyone's? The answer changes the severity and the urgency of the fix.

---

## 🔗 References

- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Sensitive Data Exposure Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [PortSwigger Information Disclosure Research](https://portswigger.net/web-security/information-disclosure)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [PayloadsAllTheThings — Sensitive Data Exposure](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
