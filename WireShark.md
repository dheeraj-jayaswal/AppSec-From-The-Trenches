# Wireshark — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Network Protocol Analysis & Traffic Inspection
>
> **Context:** Wireshark is my tool of choice for understanding what is happening at the network level during an engagement. While Burp Suite captures HTTP/HTTPS traffic, Wireshark captures everything — raw TCP, UDP, non-HTTP protocols, cleartext credentials, malformed packets, and inter-service communication patterns that no HTTP proxy would see. In enterprise assessments with internal network access, Wireshark surfaces findings in minutes that would otherwise require hours of manual enumeration.

---

## 🧠 When Wireshark Adds Value in Enterprise Testing

```
Use Wireshark when:
  ✓ Internal network access is in scope
  ✓ Investigating cleartext protocol usage (HTTP, FTP, Telnet, SNMP)
  ✓ Analysing non-HTTP application protocols
  ✓ Verifying TLS configuration (cipher suites, certificate details)
  ✓ Capturing credentials transmitted in cleartext
  ✓ Investigating session token handling in network traffic
  ✓ Analysing WebSocket communication
  ✓ Debugging application behaviour during security testing

Not needed when:
  ✗ Standard external web application testing (Burp is sufficient)
  ✗ All traffic is HTTPS/TLS (use Burp for decrypted view)
```

---

## 🔧 Essential Display Filters for Enterprise Testing

### Protocol-Based Filters

```wireshark
# HTTP cleartext traffic (immediate finding if credentials present)
http

# All TLS/SSL traffic
ssl or tls

# DNS queries — reveals internal hostnames and services
dns

# FTP — almost always cleartext credentials
ftp or ftp-data

# Telnet — cleartext authentication
telnet

# SNMP — community strings often "public" or "private"
snmp

# SMB — Windows file sharing traffic
smb or smb2

# LDAP — directory service queries
ldap

# Database protocols
tcp.port == 1433  # Microsoft SQL Server
tcp.port == 3306  # MySQL
tcp.port == 5432  # PostgreSQL
tcp.port == 6379  # Redis
tcp.port == 9200  # Elasticsearch

# All cleartext web + management protocols combined:
http or ftp or telnet or snmp or ldap
```

### Credential Hunting Filters

```wireshark
# HTTP POST requests (form submissions — credentials)
http.request.method == "POST"

# HTTP Basic Authentication headers
http.authorization

# Find login forms being submitted
http.request.uri contains "login"
http.request.uri contains "auth"
http.request.uri contains "signin"

# FTP authentication
ftp.request.command == "USER" or ftp.request.command == "PASS"

# SNMP community strings
snmp.community

# HTTP 401 responses (auth challenges — note what service)
http.response.code == 401

# Find API bearer tokens in cleartext HTTP
http.authorization contains "Bearer"
```

### Application Traffic Analysis

```wireshark
# Track a specific host's traffic
ip.addr == 10.0.14.55

# See traffic between two specific hosts
ip.addr == 10.0.14.10 and ip.addr == 10.0.14.55

# WebSocket traffic
websocket

# HTTP/2 traffic
http2

# Large data transfers (potential exfiltration or backup traffic)
frame.len > 10000

# TCP retransmissions (connectivity issues / overloaded services)
tcp.analysis.retransmission

# Follow a TCP stream (right-click → Follow → TCP Stream)
# Shows entire conversation in human-readable form
# Essential for reconstructing HTTP sessions, credentials, API calls
```

---

## 🏢 Enterprise Testing Scenarios

### Scenario 1 — Internal Network Credential Capture

```
Setup: Internal network access via VPN
       NIC in promiscuous mode
       Wireshark capturing on internal interface

Filter: http or ftp or telnet or snmp

What to look for:
  HTTP POST to /login → follow TCP stream → extract username/password
  FTP USER / PASS commands → cleartext credentials
  SNMP community strings → "public", "private", or custom = config access
  HTTP Basic Auth → base64 decode the Authorization header

Example finding — cleartext HTTP login:
  HTTP POST /admin/login
  Content-Type: application/x-www-form-urlencoded
  Body: username=admin&password=AdminPass2024!

  → Report: Credentials Transmitted in Cleartext Over HTTP
  → Severity: High
  → Evidence: Wireshark screenshot with Follow TCP Stream view
```

### Scenario 2 — TLS/SSL Configuration Analysis

```
Filter: ssl.handshake

What to look for in SSL/TLS handshake:
  Client Hello: lists supported cipher suites the client offers
  Server Hello: which cipher the server selected
  Certificate: server certificate details

Weak cipher identification:
  Filter: ssl.handshake.ciphersuite
  Look for: RC4, DES, 3DES, NULL, EXPORT, ANON → weak ciphers
  
  Or use command line:
  tshark -r capture.pcap -Y "ssl.handshake.type == 2" \
    -T fields -e ssl.handshake.ciphersuite

TLS version check:
  Filter: ssl.record.version
  0x0301 = TLS 1.0 (deprecated — report as misconfiguration)
  0x0302 = TLS 1.1 (deprecated — report as misconfiguration)
  0x0303 = TLS 1.2 (acceptable)
  0x0304 = TLS 1.3 (best)
```

### Scenario 3 — WebSocket Security Analysis

```
WebSocket connections upgrade from HTTP:
  Filter: http.upgrade contains "websocket"
  → Find the WebSocket handshake

After upgrade — WebSocket messages:
  Filter: websocket

  Right-click a WebSocket frame → Follow → WebSocket Stream
  → See all messages in the WebSocket connection

What to look for in WebSockets:
  Authentication: is the initial WebSocket connection authenticated?
  Session token: is it sent in the upgrade request header?
  Data sensitivity: is PII or sensitive data transmitted?
  Message tampering: can you replay or modify messages? (use Burp for this)
  Reconnection auth: if connection drops, does reconnect re-authenticate?
```

### Scenario 4 — API Traffic Reconstruction

```
Capture API traffic during Burp testing session:
  Run Wireshark alongside Burp
  Wireshark captures raw TCP even for TLS (encrypted at this layer)

For non-proxied internal API traffic (microservice to microservice):
  Filter: tcp.port == 8080 or tcp.port == 9090 or tcp.port == [API_PORT]
  Follow TCP Stream → reconstruct HTTP requests/responses
  
  Findings in inter-service traffic:
  → Internal APIs called without authentication between services
  → Service credentials hardcoded in request headers
  → Internal API endpoints that are never exposed to external scanner
  → Sensitive data (PII, credentials) in inter-service API calls
```

---

## 🖥️ Command Line — tshark for Scripted Analysis

```bash
# Capture to file (headless / remote server)
tshark -i eth0 -w capture.pcap

# Capture only HTTP traffic
tshark -i eth0 -f "tcp port 80 or tcp port 8080" -w http_capture.pcap

# Extract all HTTP hosts from a capture:
tshark -r capture.pcap -Y http -T fields -e http.host | sort | uniq

# Extract HTTP POST data (form submissions):
tshark -r capture.pcap -Y "http.request.method == POST" \
  -T fields -e http.host -e http.request.uri -e http.file_data

# Extract all credentials from FTP:
tshark -r capture.pcap -Y "ftp.request.command == USER or ftp.request.command == PASS" \
  -T fields -e ftp.request.arg

# Extract TLS certificate CN (domain names in certificates):
tshark -r capture.pcap -Y "ssl.handshake.type == 11" \
  -T fields -e x509sat.uTF8String | sort -u

# Find large transfers (potential data exfiltration):
tshark -r capture.pcap -q -z conv,tcp | sort -k5 -rn | head -20
```

---

## 📋 Enterprise Report — Wireshark Finding Template

```
Finding Title: Cleartext HTTP Authentication — Admin Credentials Transmitted Without Encryption

Severity: High | CVSS: 7.5

Discovery method:
  Wireshark capture on internal network interface (eth0)
  Duration: 15 minutes during normal business hours
  Filter applied: http.request.method == "POST"

Evidence:
  [Wireshark screenshot — Follow TCP Stream view]

  Frame 1247 — POST /admin/login HTTP/1.1
  Host: admin.company.internal
  Content-Type: application/x-www-form-urlencoded

  username=administrator&password=Admin@Company2024!

Impact:
  Any attacker with network access (compromised workstation, rogue
  AP, ARP poisoning) can capture administrative credentials in cleartext.
  These credentials provide full access to the admin panel.

Remediation:
  Enforce HTTPS on all admin interfaces — redirect HTTP to HTTPS
  Implement HSTS header: max-age=31536000; includeSubDomains
  Review all internal applications for HTTP-only endpoints
```

---

## 🧭 Key Takeaways

**1. Wireshark sees what Burp cannot — inter-service and non-HTTP traffic.**
Burp captures proxied HTTP/HTTPS. Wireshark captures everything on the wire — microservice API calls that bypass the proxy, database queries on port 3306, Redis commands on port 6379, SNMP community strings. On internal network assessments, these are consistently the highest-severity findings.

**2. Follow TCP Stream is the most valuable feature for evidence collection.**
Right-click any TCP packet → Follow → TCP Stream reconstructs the entire conversation in human-readable form. This is the evidence format that goes in the report — screenshots of the full stream showing cleartext credentials or sensitive data are unambiguous and compelling.

**3. Capture with tshark on headless servers — Wireshark is not always available.**
When testing from a command line on a jump box or pivot host, tshark provides the same packet capture and analysis capability. Learn the tshark equivalents of your most-used Wireshark filters.

**4. Document the capture methodology as part of the finding.**
For every Wireshark-based finding, document: interface used, capture duration, filter applied, and specific frame number. This establishes that the finding was observed from passive capture, not injected or fabricated — important for professional report credibility.

---

## 🔗 References
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [tshark Manual](https://www.wireshark.org/docs/man-pages/tshark.html)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
