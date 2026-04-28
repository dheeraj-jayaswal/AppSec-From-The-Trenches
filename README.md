# 🛡️ AppSec From The Trenches

<div align="center">

![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=22&pause=1000&color=2E6DA4&center=true&vCenter=true&width=700&lines=Senior+Penetration+Tester+%7C+5%2B+Years;Web+%26+API+Security+Specialist;200%2B+Vulnerabilities+Discovered;Application+Security+Engineer)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)
[![Location](https://img.shields.io/badge/Location-Pune%2C%20India-FF6B6B?style=for-the-badge&logo=googlemaps&logoColor=white)](https://github.com/dheeraj-jayaswal)
[![Experience](https://img.shields.io/badge/Experience-15%2B%20Years%20in%20IT-2E6DA4?style=for-the-badge&logo=buffer&logoColor=white)](https://github.com/dheeraj-jayaswal)
[![Cert](https://img.shields.io/badge/CEH-EC--Council%20Certified-darkgreen?style=for-the-badge&logo=checkmarx&logoColor=white)](https://github.com/dheeraj-jayaswal)

</div>

---

## 👋 About Me

I'm **Dheeraj Kumar Jayaswal** — a Senior Penetration Tester and Application Security Engineer with **15+ years in IT** and **5+ years focused entirely on offensive security**.

What makes my perspective different: I started as a full-stack software developer. I've built enterprise applications in ASP.NET, designed SQL Server databases, and written the kind of code that attackers target. That developer background is my biggest advantage — I find vulnerabilities that pure security testers miss because I understand *why* the code was written the way it was, not just *that* it can be exploited.

Currently at **Infosys Limited** as Technology Lead – Offensive Security, where I've discovered **200+ critical and high vulnerabilities** across enterprise web applications and APIs.

---

## 📌 What Is This Repository?

This is my personal knowledge base — real notes, techniques, and findings from **5+ years of professional penetration testing** across enterprise environments.

Every write-up in this repository covers a vulnerability I have personally exploited in real engagements (sanitised and anonymised). This is not a copy-paste of theory. These are the notes I wish I had when I started.

Each topic includes:

| Section | What you'll find |
|---|---|
| 🔍 **What it is** | Plain-English explanation of the vulnerability |
| 🌱 **Why it exists** | The root cause — developer mistake, framework gap, or design flaw |
| ⚔️ **How to find it** | Reconnaissance and discovery methodology |
| 💥 **How to exploit it** | Step-by-step with real tool commands |
| 📋 **How to report it** | Severity rating, impact statement, remediation guidance |

---

## 🗂️ Topics Covered

### 💉 Injection Attacks
- SQL Injection (Error-based, Union-based, Blind, Time-based)
- SSRF — Server-Side Request Forgery
- XSS — Reflected, Stored, DOM-based
- Command Injection via unvalidated inputs

### 🔐 Authentication & Access Control
- Authentication Bypass techniques
- IDOR — Insecure Direct Object Reference
- Broken Access Control & Privilege Escalation
- Session Management flaws
- JWT attacks and misconfigurations

### 🌐 API Security
- REST API common vulnerabilities
- GraphQL security testing
- API authentication testing (OAuth, API Keys, Bearer tokens)
- Mass Assignment & parameter tampering
- Rate limiting bypass techniques

### 🔍 Recon & Discovery
- Subdomain enumeration methodology
- Directory and file bruteforcing
- JavaScript endpoint extraction
- Hidden parameter discovery
- Source map exposure

### 🏗️ Application Architecture Flaws
- Remote Code Execution via chained exploits
- File upload bypass techniques
- Path traversal and LFI
- Business logic vulnerabilities
- CORS misconfiguration

### 🔧 DevSecOps & Secure SDLC
- Integrating SAST into CI/CD pipelines
- DAST testing with OWASP ZAP and Burp
- Secure code review methodology
- Threat modelling for microservices

---

## 📊 By The Numbers

```
Experience        ████████████████████████████████  15+ years IT | 5+ years AppSec
Vulnerabilities   ████████████████████████████████  200+ discovered across enterprises
Applications      ████████████████████████          20+ enterprise apps tested
Severity Split    CRITICAL ████████  HIGH ████████████████  MEDIUM ████████
```

| Metric | Count |
|---|---|
| Enterprise applications tested | 20+ |
| Critical / High vulnerabilities found | 200+ |
| Engineers mentored | 15+ |
| Recurring vulns eliminated via DevSecOps | 50% reduction |
| External attack surface reduced | 35% |

---

## 🛠️ Tools I Work With

**Web & API Testing**
```
Burp Suite Pro    SQLMap    ffuf    Nuclei    Nikto    Gobuster    Amass    Subfinder
```

**Network & Infrastructure**
```
Nmap    Nessus    Metasploit    Netcat    Wireshark
```

**Password & Credential Testing**
```
Hydra    John the Ripper    Hashcat
```

**DevSecOps**
```
SonarQube    OWASP ZAP    Burp Suite    GitHub Actions    CI/CD Pipeline Integration
```

---

## 🧠 My Testing Philosophy

> *"The best penetration testers think like developers first and attackers second. If you understand why code was written a certain way, you'll always find more than a scanner ever will."*

I approach every engagement in three phases:

**1. Understand before you attack**
Read the application. Use it as a real user. Understand the business logic before touching a single tool.

**2. Manual first, tools second**
Automated scanners find what they're configured to find. The interesting bugs — the ones that make it into CVEs and hall-of-fames — are always found by thinking, not scanning.

**3. Report like a developer**
A finding that developers can't understand or reproduce is a finding that doesn't get fixed. I write reports that bridge the gap between security and engineering teams.

---

## 📚 Currently Learning

- 🎯 **OSCP** — Pursuing certification (2025–2026)
- 🏫 **IIT Kanpur** — Executive Certificate Program in Cyber Security (2025–2026)
- 🧩 **PortSwigger Web Security Academy** — Advanced labs

---

## 🏅 Certifications

| Certification | Issuer | Year |
|---|---|---|
| OSCP — Offensive Security Certified Professional | OffSec | In Progress |
| Certified Ethical Hacker (CEH) | EC-Council | 2021 |
| AWS Certified Solutions Architect – Associate | Amazon Web Services | 2022 |
| AWS Certified Cloud Practitioner | Amazon Web Services | 2022 |

---

## 📂 Repository Structure

```
AppSec-From-The-Trenches/
│
├── README.md                          ← You are here
│
├── web-application/
│   ├── SQL_Injection_exploitation.md
│   ├── IDOR_real_world_scenarios.md
│   ├── SSRF_to_internal_access.md
│   ├── Auth_bypass_techniques.md
│   └── RCE_via_chained_exploits.md
│
├── api-security/
│   ├── REST_API_common_vulns.md
│   ├── GraphQL_security_testing.md
│   └── API_auth_testing_checklist.md
│
├── recon-methodology/
│   ├── Subdomain_enumeration.md
│   ├── Directory_bruteforce.md
│   └── JS_endpoint_extraction.md
│
├── pentest-methodology/
│   └── Web_app_pentest_checklist.md
│
└── report-templates/
    └── Pentest_finding_template.md
```

---

## 🤝 Connect With Me

<div align="center">

[![LinkedIn](https://img.shields.io/badge/Let's%20connect%20on%20LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

*Open to consulting, collaboration, and security discussions.*

</div>

---

<div align="center">

*Security is not a product. It is a mindset built one vulnerability at a time.*

**#AppSec · #PenTest · #WebSecurity · #APISecuity · #OffensiveSecurity**

</div>
