# OWASP Top 10 : 2025 — Complete Notes

> **Category:** Web Application Security Foundations  
> **Level:** Beginner → Intermediate  
> **Source:** [OWASP Top 10 Official](https://owasp.org/www-project-top-ten/)

---

## What is OWASP Top 10?

OWASP (Open Worldwide Application Security Project) publishes the **Top 10 most critical web application security risks**. Every Bug Bounty Hunter, Pentester, and Developer must know this list — it defines where most vulnerabilities live.

The **2025 edition** introduced new entries and reshuffled existing ones based on real-world data from thousands of applications.

---

## The 2025 List

### A01 — Broken Access Control 🔴 CRITICAL
**What it is:** Users can access data, functions, or pages they shouldn't have permission to.

**Examples:**
- Accessing another user's account by changing a URL parameter (`/user/123` → `/user/124`)
- Viewing admin panel without admin role
- Accessing API endpoints without proper authorization

**Bug Bounty Angle:** Look for IDOR (Insecure Direct Object References), horizontal/vertical privilege escalation, missing function-level access control.

**Quick Test:**
```
GET /api/users/1001/profile  → logged in as user 1002
Does it return user 1001's data? = IDOR found!
```

---

### A02 — Security Misconfiguration 🟠 HIGH
**What it is:** Insecure default configurations, incomplete setups, open cloud storage, verbose error messages.

**Examples:**
- Default credentials (admin/admin, admin/password)
- Directory listing enabled
- Exposed `.git` folder, `.env` files
- Detailed stack traces shown to users

**Bug Bounty Angle:** Check for exposed config files, cloud storage misconfigs (S3 buckets), default creds on login pages.

**Quick Test:**
```
https://target.com/.env
https://target.com/.git/config
https://target.com/phpinfo.php
```

---

### A03 — Software Supply Chain Failures 🟠 HIGH *(NEW in 2025)*
**What it is:** Compromised third-party dependencies, malicious npm/pip packages, insecure CI/CD pipelines.

**Examples:**
- Using a library with a known backdoor
- Unverified npm packages in `package.json`
- Insecure build pipeline allowing code injection

**Bug Bounty Angle:** Check `package.json`, `requirements.txt` for outdated/vulnerable dependencies. Look for exposed CI/CD dashboards (Jenkins, GitHub Actions misconfigured).

---

### A04 — Cryptographic Failures 🟠 HIGH
**What it is:** Sensitive data exposed due to weak or missing encryption.

**Examples:**
- Passwords stored as MD5/SHA1 (no salt)
- HTTP instead of HTTPS for sensitive pages
- Weak TLS versions (TLS 1.0/1.1)
- Secrets hardcoded in source code

**Bug Bounty Angle:** Check SSL/TLS configuration, look for hardcoded API keys in JS files, check password storage via exposed database dumps.

**Quick Test:**
```bash
# Check TLS version
nmap --script ssl-enum-ciphers -p 443 target.com

# Search JS files for secrets
grep -r "api_key\|secret\|password\|token" *.js
```

---

### A05 — Injection 🔴 CRITICAL
**What it is:** Untrusted data sent to an interpreter as part of a command or query.

**Types:**
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Command Injection
- LDAP Injection
- NoSQL Injection

**Bug Bounty Angle:** Test every input field, URL parameter, HTTP header. SQLi and XSS are still the most common critical bugs in bug bounty programs.

**Quick Test:**
```
# SQLi test
' OR '1'='1
' UNION SELECT null,null,null--

# XSS test
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
```

---

### A06 — Insecure Design 🟠 HIGH
**What it is:** Security flaws baked into the architecture and design — not implementation bugs but design-level flaws.

**Examples:**
- No rate limiting on sensitive endpoints (password reset, OTP)
- Business logic flaws (buy item for negative price)
- Missing threat modeling

**Bug Bounty Angle:** Think like an attacker at design level. Test password reset flows, OTP/2FA logic, payment flows for business logic bugs.

---

### A07 — Authentication Failures 🔴 CRITICAL
**What it is:** Weaknesses in how identity is confirmed and sessions managed.

**Examples:**
- No brute-force protection on login
- Weak/predictable session tokens
- Missing MFA on sensitive accounts
- Session not invalidated after logout

**Bug Bounty Angle:** Test account takeover via password reset flaws, session fixation, JWT weaknesses, OAuth misconfigurations.

---

### A08 — Software or Data Integrity Failures 🟠 HIGH
**What it is:** Code and data that lack integrity checks — insecure deserialization, auto-updates without verification.

**Examples:**
- Deserializing untrusted Java/PHP objects → RCE
- Auto-update mechanism fetching unsigned packages
- Unsigned CI/CD pipeline artifacts

**Bug Bounty Angle:** Look for serialized objects in cookies, request bodies. Test deserialization with `ysoserial` for Java apps.

---

### A09 — Security Logging & Alerting Failures 🟢 MEDIUM
**What it is:** Insufficient logging means breaches go undetected and attackers operate freely.

**Examples:**
- Login failures not logged
- No alerts on brute-force attempts
- No audit trail for sensitive actions

**Bug Bounty Angle:** Usually informational/low severity in bug bounty, but good to document. Shows security maturity issues.

---

### A10 — Mishandling of Exceptional Conditions 🟢 MEDIUM *(NEW in 2025)*
**What it is:** Poor error handling that leaks information or creates exploitable logic flaws.

**Examples:**
- Stack traces exposed to users
- Application crashes revealing internal paths
- Exception bypassing security checks

**Bug Bounty Angle:** Trigger errors deliberately — send unexpected data types, null values, oversized inputs. Check if error messages reveal tech stack, file paths, or SQL queries.

**Quick Test:**
```
# Trigger errors
- Send null values in required fields
- Send arrays where strings expected: param[]=value
- Send very long strings (10000+ chars)
- Send special chars: !@#$%^&*()
```

---

## Bug Bounty Hunting Priority

| Priority | Risk | Why Hunt It |
|----------|------|-------------|
| 🔴 P1 | A01, A05, A07 | Critical impact, account takeover, data breach |
| 🟠 P2 | A02, A03, A04, A06, A08 | High impact, often leads to further exploitation |
| 🟢 P3 | A09, A10 | Lower severity but easy wins and good for report count |

---

## Resources to Learn More

- [OWASP Top 10 Official Docs](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Free labs for every vulnerability
- [OWASP WebGoat](https://github.com/WebGoat/WebGoat) — Intentionally vulnerable app to practice

---

## Key Takeaway

> The OWASP Top 10 is not just a list — it's your **hunting checklist**.  
> Before testing any target, mentally run through all 10 categories.  
> Most bounties come from A01, A05, and A07.

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
