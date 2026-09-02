# cURL — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — HTTP Testing & API Interaction
>
> **Context:** cURL is the most universally available HTTP testing tool in every professional's toolkit. No installation required on any server, no GUI, no proxy configuration — just direct, transparent HTTP requests with full control over every header, method, and body. I use cURL for quick manual verification of findings, API testing in environments where Burp is not available, and for generating the clean, reproducible evidence that goes directly into pentest reports.

---

## 🔧 Core Enterprise Testing Commands

### Header and Response Analysis

```bash
# Check response headers only (no body) — fast first look
curl -sI https://app.company.com

# Check headers including all redirect hops
curl -sIL https://app.company.com

# Verbose — see full request and response headers
curl -v https://app.company.com 2>&1 | head -50

# Check security headers specifically
curl -sI https://app.company.com | grep -iE \
  "content-security|strict-transport|x-frame|x-content-type|\
   referrer-policy|server|x-powered-by|set-cookie"

# Check if HTTPS redirect from HTTP is in place
curl -sI http://app.company.com | grep -i location
# Expected: Location: https://app.company.com/ (301 redirect)
# If no redirect: HTTP site accessible = Missing HSTS/redirect finding
```

### Authentication Testing

```bash
# Test unauthenticated access to API endpoint
curl -sv https://app.company.com/api/v1/users/me \
  -H "Accept: application/json" \
  2>&1 | grep -E "< HTTP|{|}"

# Test with Bearer token
curl -s https://app.company.com/api/v1/users/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..." \
  -H "Accept: application/json" | jq .

# Test with session cookie
curl -s https://app.company.com/api/v1/profile \
  -H "Cookie: session=eyJhbGciOiJIUzI1NiJ9..." | jq .

# Test basic authentication
curl -s -u admin:admin https://target.company.com/admin/

# Test if old/expired token still works (session invalidation)
# First capture valid token, log out, then replay:
curl -s https://app.company.com/api/v1/users/me \
  -H "Authorization: Bearer [SAVED_OLD_TOKEN]"
# If 200 returned = session not invalidated after logout
```

### SSRF Testing via cURL

```bash
# Test if server-side URL fetch is vulnerable to SSRF
# First confirm with Burp Collaborator, then test internal targets:

# Test AWS metadata access via SSRF vulnerable endpoint
curl -s "https://app.company.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"
# Response: ami-id, hostname, iam/ → SSRF confirmed

# Test internal service access
curl -s "https://app.company.com/api/preview?source=http://127.0.0.1:6379/"
# Redis banner in response = SSRF to internal Redis

# Test cloud metadata (Azure)
curl -s "https://app.company.com/api/fetch?url=http://169.254.169.254/metadata/instance" \
  -d "Metadata: true"
```

### HTTP Method Testing

```bash
# Test all HTTP methods on an endpoint
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
  echo -n "$method: "
  curl -sI -X $method https://app.company.com/api/v1/users \
    -o /dev/null -w "%{http_code}"
  echo ""
done

# Test DELETE without authentication
curl -sv -X DELETE https://app.company.com/api/v1/users/1042 \
  -H "Accept: application/json"
# If 200/204 without auth = Critical unauthenticated delete

# Test PUT for file upload to web root (WebDAV)
curl -sv -X PUT https://app.company.com/test.txt \
  -d "test content"
# If 200/201 = PUT method enabled = potential web shell upload
```

### CORS Testing

```bash
# Test CORS wildcard misconfiguration
curl -sv https://app.company.com/api/v1/users/me \
  -H "Origin: https://attacker.example.com" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..." \
  2>&1 | grep -i "access-control"

# Expected secure: No ACAO header or ACAO: https://app.company.com
# Vulnerable: Access-Control-Allow-Origin: https://attacker.example.com (reflected)
# Critical: Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true

# Test null origin bypass
curl -sv https://app.company.com/api/v1/profile \
  -H "Origin: null" \
  2>&1 | grep -i "access-control"
```

### Path Traversal Quick Tests

```bash
# Test for path traversal in file/path parameters
# Linux targets:
curl -s "https://app.company.com/api/download?file=../../../etc/passwd" \
  -H "Authorization: Bearer TOKEN"

# Windows targets (URL encoded):
curl -s "https://app.company.com/api/download?file=..%2F..%2F..%2FWindows%2Fwin.ini" \
  -H "Authorization: Bearer TOKEN"

# /proc/self/environ (higher value than /etc/passwd):
curl -s "https://app.company.com/api/download?file=../../../proc/self/environ" \
  -H "Authorization: Bearer TOKEN"
# If environment variables returned → credentials likely included
```

---

## 🔁 API Testing Workflows

### Complete API Endpoint Testing

```bash
# GET — retrieve resource
curl -s -X GET https://api.company.com/v1/users/1042 \
  -H "Authorization: Bearer TOKEN" \
  -H "Accept: application/json" | jq .

# POST — create resource
curl -s -X POST https://api.company.com/v1/users \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","role":"admin"}' | jq .
# Note role:admin field — test mass assignment

# PUT — update resource (another user's ID — IDOR test)
curl -s -X PUT https://api.company.com/v1/users/1041 \
  -H "Authorization: Bearer TOKEN_OF_USER_1042" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}' | jq .
# 200 response = IDOR write access confirmed

# DELETE — delete resource (another user — IDOR delete test)
curl -s -X DELETE https://api.company.com/v1/users/1041 \
  -H "Authorization: Bearer TOKEN_OF_USER_1042"
# 200/204 = IDOR delete confirmed = Critical
```

### Generating Clean PoC Evidence for Reports

```bash
# This exact format goes in pentest reports — reproducible and clear

# Example IDOR PoC:
echo "=== Request ==="
curl -v -s \
  -X GET "https://app.company.com/api/v1/invoices/8823" \
  -H "Authorization: Bearer STANDARD_USER_TOKEN" \
  -H "Accept: application/json" \
  2>&1

echo ""
echo "=== Showing we own invoice 8824, not 8823 ==="
curl -s "https://app.company.com/api/v1/users/me" \
  -H "Authorization: Bearer STANDARD_USER_TOKEN" | jq '.invoice_id'

# Report format:
# Request: GET /api/v1/invoices/8823 with Standard User token
# Expected: 403 Forbidden (different user's invoice)
# Actual: 200 OK with full invoice data for User 8823
```

---

## 🛡️ SSL/TLS Testing

```bash
# Check TLS version support
curl -sv --tlsv1.0 https://app.company.com 2>&1 | grep "SSL"
# If connects: TLS 1.0 still enabled = deprecated protocol finding

curl -sv --tlsv1.1 https://app.company.com 2>&1 | grep "SSL"
# If connects: TLS 1.1 still enabled = deprecated protocol finding

# Check cipher suites (use nmap or ssllabs for full check)
curl -sv --ciphers RC4-SHA https://app.company.com 2>&1 | grep "SSL"
# If connects with RC4: weak cipher enabled

# Verify certificate details
curl -sv https://app.company.com 2>&1 | grep -E "subject|issuer|expire|CN="
```

---

## 📋 Enterprise Report — cURL Evidence Standard

```
cURL commands are the preferred format for "Steps to Reproduce" sections
in enterprise reports because they are:
  → Copy-paste reproducible by any tester or developer
  → Platform-independent (works on Linux, Mac, Windows WSL)
  → Version-controllable — exact same request every time
  → Unambiguous — no UI interactions, no browser state

Template for report Steps to Reproduce:

Step 1: Establish baseline (your own resource):
  curl -s "https://app.company.com/api/invoices/8824" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | jq '.owner_id'
  # Returns: 1099 (your own user_id)

Step 2: Access victim's resource (IDOR):
  curl -s "https://app.company.com/api/invoices/8823" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | jq .
  # Returns: Full invoice data for user 1042 (different user)

Step 3: Confirm this is a different user's data:
  curl -s "https://app.company.com/api/invoices/8823" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | jq '.owner_id'
  # Returns: 1042 (not 1099) — confirmed access to another user's invoice
```

---

## 🧭 Key Takeaways

**1. cURL is the universal PoC language — use it in every report.**
A Burp screenshot proves you found a vulnerability. A cURL command proves anyone can reproduce it. Always include the cURL equivalent of your Burp findings in the Steps to Reproduce section — developers can run it themselves to verify the fix.

**2. `-v` flag is your debugging best friend.**
`curl -v` shows the full request headers sent and response headers received. When something is not working as expected — wrong cookies, wrong content type, redirect loop — `-v` shows exactly what is happening.

**3. Pipe to `jq` for readable JSON API responses.**
`curl ... | jq .` pretty-prints JSON responses. `jq '.field'` extracts specific fields. `jq 'keys'` lists top-level keys. This makes API response analysis fast and makes report screenshots clean.

**4. Test CORS by adding the Origin header manually.**
Browsers add the Origin header automatically and handle CORS silently. cURL lets you set Origin to any value and see exactly what the server returns. This is the cleanest way to demonstrate CORS misconfiguration in a PoC.

---

## 🔗 References
- [cURL Documentation](https://curl.se/docs/)
- [cURL Man Page](https://curl.se/docs/manpage.html)
- [jq Documentation](https://jqlang.github.io/jq/)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
