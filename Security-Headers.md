# Security Response Headers — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Security Misconfiguration — OWASP A05:2021
>
> **Severity:** Low to High — individually low, but missing headers enable and amplify other vulnerabilities
>
> **Real-world impact:** Security headers are defence-in-depth controls. A missing `Content-Security-Policy` does not create an XSS vulnerability — but it removes the browser-level mitigation that would contain one. In enterprise engagements, I document missing headers not as standalone Critical findings, but as severity amplifiers: XSS + missing CSP = higher impact, missing HSTS + HTTP accessible = downgrade attack vector. Understanding what each header does — and what attacks it prevents — is what separates a complete security assessment from a checkbox exercise.

---

## 📖 The Headers That Matter in Enterprise Testing

### 1. Content-Security-Policy (CSP)

**What it does:** Restricts which sources the browser can load scripts, styles, images, and other resources from. When correctly configured, it prevents XSS execution even if an injection vulnerability exists.

```
Missing CSP header → all inline scripts and external scripts execute freely
Weak CSP ('unsafe-inline') → inline XSS still executes despite CSP presence

Secure example:
Content-Security-Policy: default-src 'self';
                          script-src 'self' https://trusted-cdn.com;
                          style-src 'self' 'unsafe-inline';
                          img-src 'self' data: https:;
                          object-src 'none';
                          base-uri 'self';
                          frame-ancestors 'none'

Testing CSP in Burp:
1. Check response headers for Content-Security-Policy
2. If present: paste into https://csp-evaluator.withgoogle.com
   → Identifies weaknesses: unsafe-inline, unsafe-eval, wildcard sources
3. If 'unsafe-inline' in script-src → CSP does not prevent XSS
4. If external domains whitelisted → check if those domains host JSONP
   → JSONP on whitelisted CDN = CSP bypass path

Reporting CSP:
  Missing entirely = Low (document, note it amplifies any XSS)
  Present but 'unsafe-inline' in script-src = Low (effectively no XSS protection)
  Present with JSONP bypass available = Medium (CSP bypassable)
  Missing CSP + active XSS found = report as combined finding, escalated severity
```

### 2. Strict-Transport-Security (HSTS)

**What it does:** Tells the browser to only ever connect to this domain over HTTPS — even if the user types `http://`. Prevents SSL stripping attacks.

```
Missing HSTS → SSL stripping attacks possible on insecure networks
Short max-age → HSTS expires quickly, brief window for attacks
Missing includeSubDomains → subdomains can still be downgraded

Secure example:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

Testing:
1. Check HTTPS responses for HSTS header
2. If missing: try HTTP version of the site — does it load? (no redirect = worst case)
3. If max-age < 1 year: note in report
4. Check for HSTS on login page specifically — credentials in transit without HSTS = High

Vulnerability impact:
  Missing HSTS on banking/finance application = High (credentials in transit)
  Missing HSTS on low-sensitivity internal tool = Low
```

### 3. X-Frame-Options / frame-ancestors CSP

**What it does:** Prevents the page from being embedded in an iframe on another domain — blocks clickjacking attacks.

```
Missing X-Frame-Options → clickjacking attacks possible

Secure examples:
X-Frame-Options: DENY              ← cannot be framed anywhere
X-Frame-Options: SAMEORIGIN        ← only same-origin framing allowed
Content-Security-Policy: frame-ancestors 'none'  ← modern equivalent (preferred)

Testing clickjacking PoC:
<html>
<body>
  <iframe src="https://target.com/account/transfer"
          style="opacity:0.0;position:absolute;top:0;left:0;
                 width:500px;height:500px;z-index:2">
  </iframe>
  <button style="position:absolute;top:250px;left:200px;z-index:1">
    Click to Win Prize!
  </button>
</body>
</html>

If iframe loads the target page → clickjacking PoC confirmed

Reporting:
  Missing on sensitive action pages (payment, account settings) = Medium
  Missing on informational pages only = Low
  Confirmed clickjacking PoC on state-changing action = Medium-High
```

### 4. X-Content-Type-Options: nosniff

**What it does:** Prevents MIME type sniffing — forces browser to use declared Content-Type, not guess from file content.

```
Missing → MIME confusion attacks possible
         Browser may execute a JavaScript file served as text/plain
         Or render HTML from a file served as image/jpeg

Secure:
X-Content-Type-Options: nosniff

Impact context:
  If application allows file upload + missing nosniff:
  → Upload a JavaScript file disguised as image.jpg
  → Browser sniffs content → executes as script
  → XSS via MIME confusion

  Always document in conjunction with file upload findings.
```

### 5. Referrer-Policy

**What it does:** Controls what URL is sent in the Referer header when users click links, preventing sensitive URL leakage to third parties.

```
Missing or 'unsafe-url' → full URL (including tokens, session IDs, PII) sent to third parties

Secure:
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: no-referrer

Problem scenario:
  URL: https://app.company.com/reset?token=abc123&email=admin@company.com
  User clicks link to external resource on this page
  Referer: https://app.company.com/reset?token=abc123&email=admin@company.com
  → Password reset token leaked to external site in Referer header

  Check URLs for tokens, IDs, PII in query params — then check Referrer-Policy
```

### 6. Permissions-Policy (formerly Feature-Policy)

**What it does:** Controls which browser features the page can access — camera, microphone, geolocation, payment APIs.

```
Missing → page can request camera, microphone, geolocation from users
Secure:
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()

Relevance in enterprise testing:
  Financial platforms: payment=() should be set
  Healthcare platforms: camera=(), microphone=() should be restricted
  Absence is Low severity but worth documenting for compliance
```

---

## 🔧 Testing All Headers in One Request

```
curl -I https://target.company.com | grep -iE \
  "Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|\
   X-Content-Type-Options|Referrer-Policy|Permissions-Policy|X-Powered-By|Server"

Or use SecurityHeaders.com:
  https://securityheaders.com/?q=target.company.com
  → Grades A+ through F with explanation of each missing header

In Burp Suite:
  HTTP History → response headers column → filter for any request
  Or: Burp Pro → Scan → passive scan highlights missing security headers
```

---

## 📋 How to Report Security Headers in Enterprise Engagements

**Individual missing header = Low severity (almost always)**

Do not file 6 separate Low findings for 6 missing headers. Group them:

```
Finding Title: Missing HTTP Security Response Headers

Severity: Low

Affected URLs: All application responses

Headers Missing:
  Content-Security-Policy
  X-Frame-Options
  X-Content-Type-Options
  Referrer-Policy
  Permissions-Policy

Headers Present:
  Strict-Transport-Security ✓

Impact:
  Missing CSP removes browser-level XSS mitigation.
  Missing X-Frame-Options enables clickjacking on sensitive pages.
  Missing X-Content-Type-Options enables MIME confusion in file upload flows.
  These are defence-in-depth controls — absence amplifies other vulnerabilities.

Remediation (ASP.NET Core):
```

```csharp
// In Program.cs — add all security headers as middleware
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Add("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    context.Response.Headers.Remove("X-Powered-By");
    context.Response.Headers.Remove("Server");
    await next();
});
```

---

## 🧭 Key Takeaways

**1. Headers are multipliers, not standalone findings.**
A missing CSP header is Low severity. XSS + missing CSP is higher severity because there is no browser-level containment. Always note missing headers when you document other vulnerabilities — they affect the combined impact rating.

**2. Evaluate CSP quality, not just presence.**
Many enterprise applications have a CSP header that is effectively useless — `Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'` allows everything. Always paste the CSP into the Google CSP Evaluator to assess actual protection level.

**3. Remove version-disclosing headers — they are easy wins for developers.**
`Server: Apache/2.4.49` and `X-Powered-By: ASP.NET 4.0.30319` tell attackers exactly which CVEs to check. Removing them is a one-line configuration change with no functional impact. Always include this in remediation advice.

---

## 🔗 References
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com)
- [SecurityHeaders.com](https://securityheaders.com)
- [MDN HTTP Headers Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
