# Enterprise Web Application Penetration Testing Methodology

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Professional Methodology — End-to-End Engagement Framework
>
> **Context:** This is the complete methodology I follow on every enterprise web application penetration test — from scope review through to report delivery. It reflects six years of engagements across BFSI, healthcare, retail, and technology clients. The structure ensures consistent coverage, professional evidence collection, and reports that developers can act on.

---

## 🧠 What Makes Enterprise Testing Different From Bug Bounty

```
Bug bounty hunting:
  → Find one vulnerability → report → get paid
  → Depth over breadth → chase the highest payout
  → No methodology required → find your own path
  → No formal scoping → test what you can

Enterprise penetration testing:
  → Test complete application surface systematically
  → Breadth AND depth → find everything in scope
  → Consistent methodology → reproducible, defensible results
  → Formal scoping → defined targets, rules of engagement
  → Professional report → findings developers can act on
  → Risk-rated output → CVSS scores, business impact statements
  → Remediation guidance → concrete steps, secure code patterns

The methodology is what separates a professional engagement
from a skilled individual doing their best ad hoc.
```

---

## 📋 Phase 0 — Pre-Engagement (Before Day 1)

```
Activities before testing begins:

1. Scope document review:
   → What is in scope: domains, IP ranges, applications, APIs
   → What is explicitly out of scope: production data, third-party services
   → Rules of engagement: testing hours, rate limiting, notification contacts
   → Emergency contacts: who to call if testing causes service disruption

2. Credentials and test accounts:
   → Obtain test accounts for each user role (admin, standard user, guest)
   → Confirm credentials work before engagement start
   → Request separate accounts per tester (audit trail cleanliness)

3. Environment confirmation:
   → Is testing against production, staging, or dedicated test environment?
   → What monitoring is in place? (inform SOC to avoid false incident)
   → What is the expected traffic baseline? (rate limiting calibration)

4. Tool and environment setup:
   → Burp Suite Pro project file created
   → Extensions installed: Autorize, JWT Editor, Param Miner, JS Miner
   → Collaborator client running
   → Note-taking structure ready (findings log)
   → VPN or network access verified

Pre-engagement is complete when:
   ✓ Written scope approval received
   ✓ All test credentials verified
   ✓ SOC notification sent if required
   ✓ Testing environment confirmed
```

---

## 🔍 Phase 1 — Reconnaissance (Hours 1-3)

```
1.1 OSINT — Passive (no contact with target):
  □ Certificate transparency (crt.sh) → subdomain enumeration
  □ Shodan/Censys → exposed services and versions
  □ Google dorking → indexed sensitive files and admin panels
  □ GitHub search → leaked credentials, config files
  □ HIBP check → domain in breach databases
  Output: complete subdomain/IP list, technology stack, known exposures

1.2 DNS and Network Mapping:
  □ DNS records (A, MX, TXT, CNAME, SPF)
  □ ASN and IP range identification
  □ Subdomain probing with httpx → identify live hosts

1.3 Technology Fingerprinting:
  □ Response headers: Server, X-Powered-By, X-AspNet-Version
  □ Cookie names: PHPSESSID (PHP), JSESSIONID (Java), .ASPXAUTH (.NET)
  □ Error page content: framework error messages
  □ HTML source: meta generators, framework comments
  □ whatweb or wappalyzer for automated fingerprinting
  Output: confirmed tech stack → informs wordlist and payload selection

1.4 Application Mapping (Burp Spider + manual browsing):
  □ Browse entire application as each user role
  □ Map all pages, forms, API endpoints, file downloads
  □ Note authentication flow, session management approach
  □ Identify all input points (URL params, POST body, headers, cookies)
  Output: complete Burp site map, list of all input vectors
```

---

## 🕵️ Phase 2 — Automated Discovery (Parallel to Phase 1)

```
Running in background while manual recon proceeds:

2.1 Directory and Content Enumeration:
  → gobuster dir with raft-medium + tech-specific wordlist
  → ffuf for API version and endpoint discovery
  → Nikto for web server misconfiguration scan
  Output: hidden paths, admin panels, config files, API endpoints

2.2 Burp Active Scan (scoped):
  → Passive scan running throughout (zero additional load)
  → Active scan on key endpoints (not production-wide unless approved)
  → Configure: all injection types, parameter fuzzing
  Output: candidate injection points (require manual verification)

2.3 Autorize Setup:
  → Configure victim user's session token
  → Browse application as admin with Autorize monitoring
  Output: automated IDOR/access control bypass candidates

2.4 Param Miner:
  → Run on key endpoints: login, profile, search, admin
  Output: hidden parameters not in UI

Review automation results after 1-2 hours → prioritise manual testing targets
```

---

## 💥 Phase 3 — Manual Testing (Core of the Engagement)

### Testing Order — By Severity Potential

```
Round 1 — Authentication and Access Control (highest impact):
  □ IDOR testing on all object references (with Autorize + manual)
  □ Authentication bypass attempts
  □ JWT attack suite (alg:none, weak secret, kid injection)
  □ Session management (fixation, invalidation, cookie flags)
  □ Privilege escalation (vertical IDOR, mass assignment)
  □ MFA bypass (response manipulation, direct endpoint access)

Round 2 — Injection Vulnerabilities:
  □ SQL injection (all input parameters — manual first, SQLMap after confirm)
  □ XSS (stored, reflected, DOM-based, blind XSS with Collaborator)
  □ SSRF (URL parameters, webhook configs, image import, PDF generation)
  □ Path traversal (file/path parameters, download endpoints)
  □ Command injection (ping, traceroute, file processing parameters)

Round 3 — Application Logic and Data Handling:
  □ Business logic flaws (quantity manipulation, workflow bypass, race conditions)
  □ Sensitive data exposure (API response over-fetching, error messages)
  □ CSRF testing (all state-changing POST/PUT/DELETE endpoints)
  □ File upload security (type validation, path, execution)
  □ API security (GraphQL introspection, versioning, batching)

Round 4 — Configuration and Infrastructure:
  □ Security misconfiguration (Spring Actuator, Swagger, default creds)
  □ Security headers (CSP, HSTS, X-Frame-Options)
  □ Cookie security flags (HttpOnly, Secure, SameSite)
  □ TLS/SSL configuration
  □ CORS misconfiguration

Per finding — evidence collection standard:
  □ Screenshot of original request (unmodified)
  □ Screenshot of modified request showing attack payload
  □ Screenshot of response showing impact
  □ CVSS score calculation
  □ Brief impact statement written immediately (don't wait for report phase)
```

---

## 📊 Phase 4 — Risk Rating Framework

```
CVSS v3.1 Base Score Calculation:

Attack Vector (AV):
  N (Network):  Exploitable remotely over internet
  A (Adjacent): Requires same network segment
  L (Local):    Requires local system access
  P (Physical): Requires physical access

Attack Complexity (AC):
  L (Low):  No special conditions — reliably exploitable
  H (High): Specific conditions required

Privileges Required (PR):
  N (None):  No authentication needed
  L (Low):   Standard user authentication
  H (High):  Admin authentication

User Interaction (UI):
  N (None):  No user interaction needed
  R (Required): Victim must perform action

Scope (S):
  U (Unchanged): Impact within the vulnerable component
  C (Changed):   Impact extends beyond the vulnerable component

Confidentiality / Integrity / Availability (C/I/A):
  N (None):   No impact
  L (Low):    Partial/limited impact
  H (High):   Complete/severe impact

Enterprise severity mapping:
  CVSS 9.0-10.0 = Critical → Immediate action, emergency patching
  CVSS 7.0-8.9  = High    → Fix within 7 days
  CVSS 4.0-6.9  = Medium  → Fix within 30 days
  CVSS 0.1-3.9  = Low     → Fix in next release cycle
  CVSS 0        = Info    → No immediate action required
```

---

## 📝 Phase 5 — Report Writing

### Finding Structure (Every Finding)

```
1. Finding Title
   → Specific, not generic
   → Bad:  "SQL Injection"
   → Good: "SQL Injection in Report Export Endpoint — Database Credential Exposure"

2. Severity and CVSS Score
   → Include full CVSS vector string: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

3. Affected Endpoint / Component
   → Exact URL, parameter name, HTTP method

4. Vulnerability Description (3-5 sentences)
   → What the vulnerability is
   → Why it exists (root cause)
   → What an attacker can do with it

5. Steps to Reproduce
   → Numbered list, reproducible exactly
   → Include exact HTTP request with payload
   → Include expected response

6. Proof of Concept
   → Screenshot or HTTP request/response pair
   → Should be self-explanatory to a reader who was not present

7. Business Impact
   → In business terms, not technical
   → Bad:  "Attacker can execute SQL commands"
   → Good: "Any authenticated user can extract the complete customer database
           including 50,000 records of name, email, and payment information,
           constituting a reportable data breach under GDPR Article 33"

8. Remediation
   → Specific, actionable steps
   → Secure code example in the application's language
   → Priority: Immediate / Short-term / Long-term

9. References
   → OWASP, CWE, CVE where relevant
```

### Report Executive Summary

```
The executive summary is the section the CISO reads.
Technical findings come second.

Contents:
  → Engagement overview (scope, dates, methodology)
  → Risk posture summary (X Critical, Y High, Z Medium, W Low)
  → Top 3 most important findings in plain language
  → Comparison to industry standard (how does this app compare?)
  → Priority remediation roadmap (what to fix first)
  → Positive findings (what is working well)

Length: 1-2 pages maximum
Language: No technical jargon — business impact focus
```

---

## ✅ Phase 6 — Post-Engagement

```
Deliverables:
  □ Draft report → client review (5 business days to respond)
  □ Incorporate client feedback → final report
  □ Remediation walkthrough meeting (if in scope)
  □ Retain evidence securely for 90 days per standard retention policy
  □ Confirm all test credentials have been revoked

Retest (if in scope):
  □ Client implements fixes
  □ Retest all High and Critical findings
  □ Issue retest addendum: "FIXED" or "PARTIALLY FIXED" or "NOT FIXED"
  □ Final report with retest results

Knowledge transfer (if requested):
  □ Developer training session on top finding types
  □ Secure coding guidelines document
  □ SDLC integration recommendations
```

---

## 🗂️ Engagement Daily Checklist

```
Day 1 morning:
☐ Confirm test credentials work
☐ Configure Burp: scope, project, extensions
☐ Start Nikto and directory enumeration in background
☐ Begin manual application walkthrough

Day 1 afternoon:
☐ Review automation results
☐ Begin authentication and access control testing
☐ Set up Autorize, configure victim token

Day 2:
☐ Complete authentication testing
☐ Begin injection vulnerability testing
☐ Collect evidence for all confirmed findings

Day 3 (penultimate day):
☐ Complete all testing — no new vulnerability categories
☐ Verify all findings are reproducible
☐ Ensure evidence is complete for every finding

Day 4 (final day / report day):
☐ Write report
☐ CVSS score every finding
☐ Secure code fixes for every finding
☐ Executive summary draft
```

---

## 🧭 Key Takeaways From 6+ Years of Enterprise Engagements

**1. Methodology is the difference between a good engagement and a great one.**
The best vulnerability you find on day 3 is worth nothing if you missed a Critical on day 1 because you were not systematic. The methodology ensures that access control testing happens before injection testing — because an IDOR that exposes credentials changes how you approach every subsequent test.

**2. Evidence collection is non-negotiable — collect it the moment you find something.**
After a 10-hour testing day, you will not remember the exact request that demonstrated the finding. Screenshot immediately. Name Burp Repeater tabs. Export request/response pairs as you confirm each finding. The 30 seconds of discipline in the moment saves 30 minutes of reconstruction at report time.

**3. Write the business impact statement before you write the technical description.**
The technical details are easy — you just described what you did. The business impact is what takes thought. What data is exposed? How many records? What regulations apply? What can the attacker actually do with this? Write that first, and the technical description follows naturally.

**4. The remediation section is what justifies the engagement fee.**
A pentest report without actionable remediation is just a list of problems. The value to the client is knowing how to fix them. For every finding, provide a concrete remediation action and a secure code example in the application's language. This is what gets findings actually fixed rather than deprioritised.

**5. Retest everything High and Critical before the final report.**
"Fixed" in a retest addendum is worth more to the client than the original finding. It closes the loop. It gives the development team credit for the remediation work. And it catches the cases where the fix introduced a new vulnerability or only partially addressed the original. Retesting is part of the professional obligation.

---

## 🔗 References
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES Technical Guidelines](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
