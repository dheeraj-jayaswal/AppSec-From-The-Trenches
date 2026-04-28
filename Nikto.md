# Nikto — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Web Server Security Scanner
>
> **Context:** Nikto is a lightweight, fast web server scanner that I run in the first 15 minutes of every enterprise engagement alongside my manual recon. It excels at one specific task — identifying known dangerous files, misconfigurations, outdated software, and security header gaps across web servers quickly. It is not a substitute for manual testing or Burp Suite, but as a rapid misconfiguration scanner it consistently surfaces findings that would otherwise require manual checking of hundreds of paths.

---

## 📖 What Nikto Is (and Is Not)

```
Nikto IS good at:
  ✓ Identifying dangerous files and default paths (phpinfo.php, /admin, /.git/)
  ✓ Version fingerprinting of web servers and frameworks
  ✓ Detecting missing security headers
  ✓ Finding known outdated software versions with CVEs
  ✓ Discovering backup files, exposed configuration files
  ✓ HTTP method testing (PUT, DELETE enabled?)
  ✓ SSL/TLS configuration issues
  Fast: runs in 2-5 minutes on most enterprise targets

Nikto is NOT good at:
  ✗ Deep vulnerability analysis (use Burp for this)
  ✗ Authenticated scanning (limited session support)
  ✗ Modern web applications (React/SPA apps have few static paths)
  ✗ API security testing (Burp or ZAP API scan is better)
  ✗ Low false positive rate (requires manual verification of all findings)
  ✗ Stealthy scanning (generates very obvious logs — do not use for stealth)
```

---

## 🔧 Core Commands for Enterprise Engagements

### Basic Scan

```bash
# Standard scan against a target
nikto -h https://target.company.com

# HTTP target
nikto -h http://target.company.internal

# Specific port
nikto -h https://target.company.com:8443

# Save output to file (always do this for evidence)
nikto -h https://target.company.com -output nikto_results.txt

# HTML report (better for client reports)
nikto -h https://target.company.com -output nikto_report.html -Format html
```

### Authenticated Scanning

```bash
# With cookie (capture session cookie from Burp first)
nikto -h https://app.company.com \
  -Cookies "session=eyJhbGciOiJIUzI1NiJ9..."

# With basic auth
nikto -h https://admin.company.com -id admin:password

# With custom headers (Bearer token)
nikto -h https://api.company.com \
  -useragent "Mozilla/5.0 (Enterprise-Pentest)" \
  -Cookies "" \
  -key "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."
```

### Enterprise-Specific Scan Options

```bash
# Scan with specific tuning (select vulnerability categories):
# -T 1: Interesting files/seen in logs
# -T 2: Misconfiguration / Default Files
# -T 3: Information disclosure
# -T 4: Injection (XSS/Script/HTML)
# -T 5: Remote file retrieval (inside webroot)
# -T 6: Denial of service
# -T 7: Remote file retrieval (server wide)
# -T 8: Command execution
# -T 9: SQL injection
# -T b: Software identification
# -T c: Remote source inclusion
# -T x: Reverse tuning (test everything except selected)

# For enterprise engagement — focus on high-value categories:
nikto -h https://target.company.com -T 2378b -o nikto_report.html -Format html
# 2=Misconfig, 3=Info disclosure, 7=File retrieval, 8=Command exec, b=Software ID

# Scan through Burp proxy (recommended — captures all Nikto traffic):
nikto -h https://target.company.com \
  -useproxy http://127.0.0.1:8080 \
  -output nikto_burp.txt

# Scan only specific path (useful for targeted directory testing):
nikto -h https://target.company.com/admin/ -output nikto_admin.txt
```

### Multiple Target Scanning

```bash
# Scan from a file containing multiple hosts
cat > targets.txt << EOF
https://app1.company.com
https://app2.company.com
https://api.company.com
https://admin.company.com
EOF

nikto -h targets.txt -output nikto_all.txt -Format txt
```

---

## 🔍 Interpreting Nikto Output

```
Sample Nikto output with annotations:

- Nikto v2.1.6
+ Target IP:          10.0.14.23
+ Target Hostname:    app.company.com
+ Target Port:        443

+ Server: Microsoft-IIS/8.5
  → Version disclosure — check NVD for IIS 8.5 CVEs
  → Report as: Information Disclosure — Server Version Revealed

+ The X-Frame-Options header is not present.
  → Missing header — clickjacking possible
  → Report as: Missing X-Frame-Options Header (Low)

+ The X-Content-Type-Options header is not present.
  → Missing nosniff — MIME confusion attacks possible

+ /admin/: Admin login page/section found.
  → Investigate manually — default credentials? Unprotected?

+ /web.config: ASP.NET configuration file found.
  → CRITICAL — immediately test this manually in Burp
  → Check if it returns 200 with content

+ /phpinfo.php: PHP information page found.
  → High — PHP version, server config, module details exposed

+ HTTP method DELETE allowed.
  → Investigate — should DELETE be enabled on this server?

+ Server is vulnerable to CVE-2011-3192 (Range header DoS)
  → Server version is outdated — check for patches

Prioritise Nikto findings:
  Critical: .env, web.config, phpinfo.php, /.git/config returned 200
  High:     Default credentials found, phpMyAdmin accessible, CVE findings
  Medium:   Admin panel found, directory listing, HTTP methods
  Low:      Missing headers (investigate context before rating)
  Informational: Version disclosure, standard headers
```

---

## 🏢 Nikto in My Enterprise Workflow

```
When I use Nikto:
  → First 15 minutes of every engagement
  → Running in background while I manually configure Burp scope
  → Never as the primary finding source — always as a lead generator

Workflow:
  1. Start: nikto -h https://target.company.com -o nikto_initial.txt
  2. While Nikto runs: configure Burp, browse application
  3. After Nikto finishes: review output for any 200 responses on sensitive files
  4. For every Nikto finding: manually verify in Burp Repeater before reporting
  5. Never copy Nikto output directly into a report — verify everything

The "verify in Burp" rule:
  Nikto often flags files based on patterns, not actual 200 responses
  Always confirm with: curl -I https://target.company.com/path-flagged-by-nikto
  Or: Burp Repeater → GET /path-flagged → check status code and response body
  
  Nikto says /.git/config exists → Burp confirms 200 with git content → report it
  Nikto says /phpinfo.php exists → Burp returns 404 → false positive → do not report
```

---

## 📋 Nikto in Enterprise Reports

```
Include in reports:
  Full Nikto command used (for reproducibility)
  HTML report as appendix
  Manually verified findings extracted and escalated to individual findings
  
Do not include in reports:
  Raw Nikto output without verification
  False positives (verify every finding)
  Nikto's CVE suggestions without confirming the version is actually affected

Sample report note:
"Nikto web server scanner was used during the initial reconnaissance phase.
Findings from Nikto were manually verified using Burp Suite Repeater before
inclusion in this report. The tool identified [X] issues of which [Y] were
confirmed as valid findings. The full Nikto report is included as Appendix C."
```

---

## 🧭 Key Takeaways

**1. Nikto is a lead generator, not a finding generator.**
Every Nikto finding requires manual verification before it appears in a professional report. Nikto generates false positives regularly — particularly on IIS servers that return 200 with custom error pages for any URL. Always confirm with Burp or curl.

**2. Run Nikto in the background — it should not slow down your testing.**
Start Nikto at the beginning of the engagement and let it run while you configure Burp and begin manual testing. By the time you are ready to investigate misconfiguration, Nikto has finished. This adds zero dead time to the engagement.

**3. Nikto through Burp proxy = complete evidence trail.**
Using `--useproxy http://127.0.0.1:8080` routes all Nikto traffic through Burp HTTP History. This means every Nikto request and response is captured in your project file — useful for reports and for investigating interesting Nikto findings interactively in Repeater.

**4. Modern SPAs return minimal value from Nikto.**
React, Angular, and Vue applications serve mostly static assets and make API calls — they have few traditional server-side paths for Nikto to discover. For modern enterprise apps, Nikto is most useful for finding server-level issues (headers, IIS/Apache config) rather than application-level paths.

---

## 🔗 References
- [Nikto Documentation](https://cirt.net/Nikto2)
- [Nikto GitHub](https://github.com/sullo/nikto)
- [Nikto Tuning Options](https://github.com/sullo/nikto/wiki/Tuning-options)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
