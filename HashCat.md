# Hashcat — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Password Hash Cracking & Policy Validation
>
> **Context:** Hashcat appears in enterprise penetration tests in two specific scenarios: when hashed credentials are exposed through a SQL injection finding or database access (demonstrating the impact of weak password storage), and when testing JWT HS256 signing secrets. The goal is always to demonstrate real-world impact — not to enumerate credentials for misuse. Every hash I crack in an engagement is cracked to prove a business risk, not to access systems beyond what is needed to prove the vulnerability.

---

## 📖 Hash Identification — First Step Before Cracking

```bash
# Use hashid or hash-identifier to identify unknown hash format
hashid '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
# Output: [+] Blowfish(OpenBSD) [+] Bcrypt

hashid '5f4dcc3b5aa765d61d8327deb882cf99'
# Output: [+] MD5

# Hashcat mode reference — most common in enterprise:
# -m 0     MD5 (old/legacy apps)
# -m 100   SHA-1 (legacy)
# -m 1400  SHA-256 (common)
# -m 1800  sha512crypt $6$ (Linux shadow)
# -m 3200  bcrypt $2*$ (modern web apps — very slow)
# -m 1000  NTLM (Windows / Active Directory)
# -m 5500  NetNTLMv1 (Windows network auth)
# -m 5600  NetNTLMv2 (Windows network auth — most common)
# -m 16500 JWT HS256 (token signing secret)
# -m 500   md5crypt $1$ (Linux/Apache legacy)
# -m 400   phpass $P$ (WordPress / Drupal)
```

---

## 🔧 Core Cracking Commands

### Dictionary Attack (Most Common in Enterprise)

```bash
# MD5 with rockyou.txt (fast — weak hash)
hashcat -a 0 -m 0 hashes.txt /usr/share/wordlists/rockyou.txt \
  --force -O

# SHA-256 with best64 rules (amplifies wordlist with common mutations)
hashcat -a 0 -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# bcrypt (slow by design — use targeted wordlist, not rockyou)
hashcat -a 0 -m 3200 bcrypt_hashes.txt targeted_wordlist.txt \
  --force

# NTLM (Windows — fast to crack)
hashcat -a 0 -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# NetNTLMv2 (captured from network — use large wordlist)
hashcat -a 0 -m 5600 netntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/dive.rule
```

### JWT HS256 Secret Cracking

```bash
# Extract JWT from Burp Suite → paste into jwt_tokens.txt
# Format: full JWT token (all three parts with dots)

hashcat -a 0 -m 16500 jwt_tokens.txt /usr/share/wordlists/rockyou.txt \
  --force

# Also test common enterprise JWT secrets:
cat > jwt_secrets.txt << 'EOF'
secret
password
changeme
jwt_secret
jwttoken
mysecret
myapp
appname
1234567890
supersecret
your-256-bit-secret
EOF

hashcat -a 0 -m 16500 jwt_tokens.txt jwt_secrets.txt --force

# If cracked: output shows token + cracked secret
# Example: eyJhbGci...:secret
# → Now you can forge any JWT payload signed with "secret"
```

### Rule-Based Attack (Dictionary + Mutations)

```bash
# Rules modify wordlist entries with common patterns:
# P@ssword, P@ssw0rd, Password1, Password!, etc.

# OneRuleToRuleThemAll — comprehensive rules
hashcat -a 0 -m 0 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# Multiple rules combined
hashcat -a 0 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/toggles1.rule

# Most useful built-in rules for enterprise testing:
# best64.rule          → 64 most effective rules
# OneRuleToRuleThemAll → large comprehensive rule set
# dive.rule            → deep mutation rules
# toggles1-5.rule      → case toggling
```

### Targeted Wordlist for Enterprise Environments

```bash
# Enterprise users often use company-name-based passwords
# Build a targeted wordlist from reconnaissance intel

cat > enterprise_passwords.txt << 'EOF'
Company2024
Company@2024
Company2024!
CompanyAdmin
CompanyAdmin1
Welcome1
Welcome@1
Welcome2024
Infosys@123
Password1
Password@1
Winter2024
Summer2024
Spring2024
Admin@123
Admin2024!
EOF

# Run targeted list first (fast, high success rate for enterprise)
hashcat -a 0 -m 0 hashes.txt enterprise_passwords.txt --force
hashcat -a 0 -m 1400 hashes.txt enterprise_passwords.txt \
  -r /usr/share/hashcat/rules/best64.rule --force
```

### Mask Attack (Pattern-Based)

```bash
# When password policy is known: 8+ chars, uppercase, lowercase, number, special
# ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all

# 8-char pattern: Capital + 5 lowercase + 2 digits
hashcat -a 3 -m 0 hashes.txt '?u?l?l?l?l?l?d?d' --force

# Common corporate pattern: Company + year + symbol
hashcat -a 3 -m 0 hashes.txt 'Company?d?d?d?d!' --force

# Policy-compliant pattern testing:
hashcat -a 3 -m 0 hashes.txt '?u?l?l?l?l?l?d?s' --force
# e.g.: Passw0rd!, Admin123@, Secret99#
```

---

## 🏢 Enterprise Testing Scenarios

### Scenario 1 — SQL Injection Impact Demonstration

```bash
# Finding: SQL injection in /api/reports endpoint
# Database: users table with password_hash column
# Action: Extract 3 sample hashes to demonstrate weak storage

# Extracted hashes (3 rows only — minimum for PoC):
cat > sample_hashes.txt << 'EOF'
5f4dcc3b5aa765d61d8327deb882cf99
e10adc3949ba59abbe56e057f20f883e
827ccb0eea8a706c4c34a16891f84e7b
EOF

# Identify hash type:
hashid 5f4dcc3b5aa765d61d8327deb882cf99
# → MD5

# Crack:
hashcat -a 0 -m 0 sample_hashes.txt /usr/share/wordlists/rockyou.txt --force

# Results:
# 5f4dcc3b5aa765d61d8327deb882cf99:password
# e10adc3949ba59abbe56e057f20f883e:123456
# 827ccb0eea8a706c4c34a16891f84e7b:12345678

# Report evidence:
# "Extracted MD5 password hashes from the users table via SQL injection.
# Cracked 3 of 3 sample hashes in under 5 seconds using a common wordlist.
# Passwords were: 'password', '123456', '12345678'.
# Finding: MD5 without salt is an outdated hashing algorithm — bcrypt required."
```

### Scenario 2 — JWT Secret Cracking Impact

```bash
# Finding: JWT tokens used for authentication
# JWT header: {"alg":"HS256","typ":"JWT"}
# Action: Attempt to crack the signing secret

# Save JWT token:
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZGhlZXJhaiIsInJvbGUiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" > jwt.txt

# Crack:
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --force

# If cracked (e.g. secret = "secret123"):
# → Can now forge any JWT:
# → {"user":"admin","role":"admin"} signed with "secret123"
# → Full administrative access to any account

# Report:
# "The JWT signing secret was cracked in [X] seconds using rockyou.txt.
# The cracked secret is: 'secret123'. An attacker can forge authentication
# tokens for any user, including administrators, without valid credentials."
```

---

## 📋 Enterprise Report Template

```
Finding Title: Weak Password Hashing — MD5 Without Salt Enables Rapid Credential Recovery

Severity: High | CVSS: 7.5

Context:
  Hashes obtained via SQL injection finding (see Finding #1)
  3 sample hashes extracted from users table for impact demonstration

Evidence:
  Hash algorithm: MD5 (no salt)
  Hashcat command: hashcat -a 0 -m 0 sample_hashes.txt rockyou.txt
  Time to crack 3 hashes: 4 seconds
  Results:
    5f4dcc3b5aa765d61d8327deb882cf99 → "password"
    e10adc3949ba59abbe56e057f20f883e → "123456"
    827ccb0eea8a706c4c34a16891f84e7b → "12345678"

Impact:
  All 3 sample passwords cracked in under 5 seconds.
  MD5 without salt allows rainbow table and dictionary attacks.
  In a full database exposure scenario, all user passwords would be
  recoverable, enabling credential stuffing against other platforms
  where users reuse passwords.

Remediation:
  Migrate to bcrypt (cost factor ≥ 12), Argon2id, or scrypt
  Never use MD5, SHA-1, or unsalted hashes for password storage
  Implement password strength requirements (min 12 chars, complexity)
  Force password reset for all users after migration
```

---

## 🧭 Key Takeaways

**1. Hash identification comes before cracking — always.**
Running hashcat on the wrong mode wastes GPU time and returns no results. `hashid` or `hash-identifier` identifies the format in seconds. Know the mode before running.

**2. Crack the minimum number of hashes needed to prove the point.**
3 hashes proving MD5 storage with weak passwords is more compelling than a full table dump. Enterprise testing is about proving risk, not maximising credential recovery. Extract 3-5 sample hashes, crack them, document the finding.

**3. JWT secret cracking is the highest-impact hashcat use in modern enterprise.**
MD5 password hashing is rare in modern enterprise apps. JWT HS256 with weak secrets is extremely common — developers copy tutorial code that uses "secret" as the example key and deploy it to production. `-m 16500` on rockyou.txt with JWT tokens is productive in a large percentage of modern API engagements.

**4. Rules multiply wordlist effectiveness for enterprise password patterns.**
Enterprise users follow policies: minimum 8 characters, uppercase, number, special character. They choose predictable patterns: `Company@2024`, `Welcome1!`, `Password123`. Rules like `best64.rule` transform `password` into `P@ssword!`, `P@ssw0rd`, `Password1` automatically.

---

## 🔗 References
- [Hashcat Documentation](https://hashcat.net/wiki/)
- [Hashcat Modes Reference](https://hashcat.net/wiki/doku.php?id=hashcat)
- [OneRuleToRuleThemAll](https://github.com/NotSoSecure/password_cracking_rules)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
