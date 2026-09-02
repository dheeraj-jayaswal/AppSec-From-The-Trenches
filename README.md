<div align="center">

# 🛡️ AppSec From The Trenches
### Pentest Tools & Methodology Reference

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)
[![Location](https://img.shields.io/badge/Location-Pune%2C%20India-FF6B6B?style=for-the-badge&logo=googlemaps&logoColor=white)](https://github.com/dheeraj-jayaswal)
[![Experience](https://img.shields.io/badge/Experience-15%2B%20Years%20IT-2ECC71?style=for-the-badge)](https://linkedin.com/in/dheerajkumarjayaswal)
[![Cert](https://img.shields.io/badge/CEH--EC--Council%20Certified-darkgreen?style=for-the-badge)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>

---

## 👋 About Me

I'm **Dheeraj Kumar Jayaswal** — a Senior Penetration Tester and Application Security Engineer with **15+ years in IT** and **6+ years focused entirely on offensive security**.

What makes my perspective different: I started as a full-stack software developer. I've built enterprise applications in ASP.NET, designed SQL Server databases, and written the kind of code that attackers target. That developer background is my biggest advantage — I find vulnerabilities that pure security testers miss because I understand *why* the code was written the way it was, not just *that* it can be exploited.

Currently at **Infosys Limited** as Technology Lead – Offensive Security.

---

## 📌 What This Repository Actually Is

This repo is my **practical tools and methodology reference** — how I actually use the tools that show up in every enterprise engagement, plus the overarching testing methodology that ties them together. It's the repo I use myself as a quick-reference during an engagement, not a theory guide.

It also includes a set of **short vulnerability quick-reference notes** — but for the full, in-depth write-ups on *why* each vulnerability class exists and how it plays out across different industries, those live in my other repos (see below). This repo's job is tools and workflow; the deep dives live elsewhere.

---

## 🧭 How This Fits With My Other Repos

| Repo | What it's for |
|---|---|
| **AppSec-From-The-Trenches** *(this repo)* | Tool usage guides, pentest methodology, and short vulnerability quick-reference notes |
| [From-Dev-To-Attacker](https://github.com/dheeraj-jayaswal/From-Dev-To-Attacker) | Full-depth original write-ups on *why* vulnerabilities exist, from a developer's lens, with enterprise domain-impact framing |
| [API-From-The-Trenches](https://github.com/dheeraj-jayaswal/API-From-The-Trenches) | Deep dive specifically into API security — OWASP API Top 10, GraphQL, BOLA, testing methodology |
| [Bug-Bounty-Hunting-Companion](https://github.com/dheeraj-jayaswal/Bug-Bounty-Hunting-Companion) | Real disclosed HackerOne reports turned into reproducible checklists |

---

## 🛠️ Tool Usage Guides

The core of this repo — how I actually run each of these tools in a real engagement, not just the man-page basics.

| Category | Tools |
|---|---|
| **Web & API Testing** | [Burp-Suites.md](Burp-Suites.md) · [OWASP-ZAP.md](OWASP-ZAP.md) · [Postman.md](Postman.md) · [FFUF.md](FFUF.md) · [CURL.md](CURL.md) |
| **Injection & Vulnerability Scanning** | [SQLMap.md](SQLMap.md) · [Nikto.md](Nikto.md) · [Nuclei.md](Nuclei.md) |
| **Network & Infrastructure** | [NMAP.md](NMAP.md) · [Nessus.md](Nessus.md) · [Metasploit.md](Metasploit.md) · [NetCat-NC.md](NetCat-NC.md) · [WireShark.md](WireShark.md) |
| **Password & Credential Testing** | [Hydra.md](Hydra.md) · [HashCat.md](HashCat.md) · [John.md](John.md) |
| **OSINT & Recon** | [OSINT & Recon-ng.md](OSINT%20%26%20Recon-ng.md) |

---

## 📐 Methodology & Recon

| Topic | File |
|---|---|
| Web Application Pentest Methodology | [WAPT-Methodology.md](WAPT-Methodology.md) |
| Bug Bounty Recon Workflow | [Bug-Bounty-Recon.md](Bug-Bounty-Recon.md) |
| Directory & File Enumeration | [Directory-Enumeration.md](Directory-Enumeration.md) |
| OWASP Top 10 Reference | [OWASP-Top10.md](OWASP-Top10.md) |

---

## 📋 Vulnerability Quick-Reference

Short-form notes for fast recall during an engagement. For the full write-up on any of these — including *why* the vulnerability exists and how its impact plays out across different industries — see [From-Dev-To-Attacker](https://github.com/dheeraj-jayaswal/From-Dev-To-Attacker).

| Topic | File |
|---|---|
| Broken Authentication | [Broken-Authentication.md](Broken-Authentication.md) |
| CSRF | [CSRF.md](CSRF.md) |
| Cookie Security | [Cookie-Security.md](Cookie-Security.md) |
| IDOR | [IDOR.md](IDOR.md) |
| Insecure Deserialization | [Insecure-Deserialization.md](Insecure-Deserialization.md) |
| JWT Attacks | [JWT-Attacks.md](JWT-Attacks.md) |
| Path Traversal | [Path-Traversal.md](Path-Traversal.md) |
| SQL Injection | [SQL-Injection.md](SQL-Injection.md) |
| SSRF | [SSRF.md](SSRF.md) |
| Security Headers | [Security-Headers.md](Security-Headers.md) |
| Security Misconfiguration | [Security-Misconfiguration.md](Security-Misconfiguration.md) |
| Sensitive Data Exposure | [Sensitive-Data-Exposure.md](Sensitive-Data-Exposure.md) |
| XSS | [XSS.md](XSS.md) |

---

## 🧠 My Testing Philosophy

> *"The best penetration testers think like developers first and attackers second. If you understand why code was written a certain way, you'll always find more than a scanner ever will."*

I approach every engagement in three phases:

**1. Understand before you attack** — Read the application. Use it as a real user. Understand the business logic before touching a single tool.

**2. Manual first, tools second** — Automated scanners find what they're configured to find. The interesting bugs are always found by thinking, not scanning.

**3. Report like a developer** — A finding that developers can't understand or reproduce is a finding that doesn't get fixed.

---

## 🏅 Certifications & Background

| Certification | Issuer | Status |
|---|---|---|
| Certified Ethical Hacker (CEH) | EC-Council | ✅ 2021 |
| AWS Certified Solutions Architect – Associate | Amazon Web Services | ✅ 2022 |
| AWS Certified Cloud Practitioner | Amazon Web Services | ✅ 2022 |
| Executive Certificate in Cyber Security | IIT Kanpur | ✅ 2026 |
| OSWE — OffSec Web Expert (OSCE3 track) | 🔄 In Progress |

**Future direction — Red Teaming:** OSCP → CRTO → OSEP, CRTP, CRTL, CRTE


**Domain experience:** Income Tax · Banking · Retail · E-commerce · Freight Logistics · Education

---

## 📄 License

[![License](https://img.shields.io/badge/license-CC%20BY%204.0-blue)](LICENSE.md)
[![Last Commit](https://img.shields.io/github/last-commit/dheeraj-jayaswal/AppSec-From-The-Trenches)](https://github.com/dheeraj-jayaswal/AppSec-From-The-Trenches/commits/main)

⭐ If this helped you, consider starring the repo — it helps others find it too.

---

## 🤝 Connect With Me

[LinkedIn](https://linkedin.com/in/dheerajkumarjayaswal) — open to consulting, collaboration, and security discussions.

---

<div align="center">

*Security is not a product. It is a mindset built one vulnerability at a time.*

**#AppSec · #PenTest · #WebSecurity · #APISecurity · #OffensiveSecurity**

</div>
