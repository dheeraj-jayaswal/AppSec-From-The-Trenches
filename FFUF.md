# ffuf — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Fast Web Fuzzer
>
> **Context:** ffuf (Fuzz Faster U Fool) is my go-to tool for web content discovery and parameter fuzzing in enterprise assessments. Compared to Gobuster and Dirsearch, ffuf is faster, more flexible, and provides better output filtering. Its ability to fuzz any position in a request — URL path, query parameters, POST body, headers — makes it versatile enough to replace multiple other tools. I use it for directory enumeration, API endpoint discovery, virtual host enumeration, and parameter fuzzing in a single tool.

---

## 🧠 Why ffuf Over Other Fuzzing Tools

```
ffuf advantages over alternatives:
  vs Gobuster:
    → ffuf fuzzes any request position (path, param, header, body)
    → Better filtering options (size, words, lines, time)
    → JSON output for programmatic processing
    → Can fuzz POST parameters natively

  vs Dirsearch:
    → Significantly faster
    → More flexible filter options
    → Better for API fuzzing
    → Cleaner output and progress display

  vs Burp Intruder (community):
    → No rate limit throttling on community version
    → Command line = scriptable and automatable
    → Faster for large wordlists

When I use ffuf vs Gobuster in practice:
  Gobuster: quick initial scans (simple, reliable)
  ffuf:     when I need filtering, POST body fuzzing, or API parameter discovery
```

---

## 🔧 Core Usage for Enterprise Testing

### Directory and Content Enumeration

```bash
# Standard directory fuzzing
ffuf -u https://app.company.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,201,301,302,401,403 \
  -o ffuf_dirs.json -of json

# With file extensions (enterprise .NET/PHP apps)
ffuf -u https://app.company.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-medium-files.txt \
  -e .asp,.aspx,.html,.js,.txt,.bak,.old,.config,.zip \
  -mc 200,201,301,302 \
  -o ffuf_files.json -of json

# Remove false positives by filtering custom 404 page size:
# Step 1: Find 404 page size
ffuf -u https://app.company.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/common.txt \
  -mc all 2>/dev/null | head -20
# Note the size of non-existent path responses

# Step 2: Filter that size from real scan
ffuf -u https://app.company.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,201,301,302,401,403 \
  -fs 2847 \
  -o ffuf_clean.json -of json
# -fs 2847: filter out responses with size = 2847 (the custom 404 size)
```

### API Endpoint Discovery

```bash
# Fuzz API endpoint names
ffuf -u https://api.company.com/api/v1/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
  -mc 200,201,401,403 \
  -H "Authorization: Bearer TOKEN" \
  -H "Accept: application/json" \
  -o api_endpoints.json -of json

# Fuzz API versions
ffuf -u https://api.company.com/FUZZ/users \
  -w versions.txt \
  -mc 200,201,401,403

# versions.txt:
# api/v1
# api/v2
# api/v3
# v1
# v2
# internal
# api/internal
# api/admin

# Fuzz HTTP methods on discovered endpoint
ffuf -u https://api.company.com/api/v1/users \
  -w methods.txt \
  -X FUZZ \
  -mc 200,201,204,405 \
  -H "Authorization: Bearer TOKEN"

# methods.txt: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE
```

### Hidden Parameter Discovery

```bash
# GET parameter fuzzing (find undocumented parameters)
ffuf -u "https://app.company.com/api/users?FUZZ=test" \
  -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -H "Authorization: Bearer TOKEN" \
  -mc 200 \
  -fs [baseline_size] \
  -o params_get.json -of json

# POST parameter fuzzing
ffuf -u https://app.company.com/api/users/update \
  -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -X POST \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "FUZZ=test" \
  -mc 200,400 \
  -fs [baseline_size] \
  -o params_post.json -of json

# JSON body parameter fuzzing (mass assignment discovery)
ffuf -u https://api.company.com/api/v1/profile \
  -w parameter_names.txt \
  -X PUT \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"FUZZ": "test_value"}' \
  -mc 200 \
  -fs [normal_response_size]
# Any response size different from normal = server processed the parameter

# parameter_names.txt (mass assignment candidates):
# role, is_admin, admin, is_verified, verified, plan, subscription,
# credits, balance, access_level, permission, account_type
```

### Virtual Host Enumeration

```bash
# Find subdomains/virtual hosts on the same IP
ffuf -u https://app.company.com \
  -H "Host: FUZZ.company.com" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,301,302 \
  -fs [baseline_size_for_unknown_vhost] \
  -o vhosts.json -of json

# Filter responses that are same as default vhost (false positives):
# First: curl -sI https://app.company.com -H "Host: nonexistent12345.company.com" | wc -c
# Note the response size → filter with -fs [that_size]
```

### Authentication Endpoint Testing

```bash
# Rate limiting detection — rapid requests to login endpoint
ffuf -u https://app.company.com/api/auth/login \
  -w /dev/null \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"wrongpassword"}' \
  -rate 10 \
  -t 10 \
  -mc all \
  -recursion-depth 0

# Better: use a list of incrementing wrong passwords
# to demonstrate no rate limiting with real variation:
ffuf -u https://app.company.com/api/auth/login \
  -w wrong_passwords.txt \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@company.com","password":"FUZZ"}' \
  -mc 200,401 \
  -rate 5 \
  -o ratelimit_test.json
```

---

## 🎛️ Filtering Mastery — The Key to Clean Results

```bash
# The four main filter/match options:
# -mc/fc: match/filter HTTP status code
# -ms/fs: match/filter response size (bytes)
# -mw/fw: match/filter response word count
# -ml/fl: match/filter response line count
# -mr:    match regex in response
# -t:     time-based filter

# Combine filters for clean results:
ffuf -u https://app.company.com/FUZZ \
  -w raft-large-directories.txt \
  -mc 200,201,301,302,401,403 \    # only these status codes
  -fs 1234,5678 \                   # exclude specific sizes (false positives)
  -fw 10 \                          # exclude responses with exactly 10 words
  -t 3 \                            # exclude responses taking > 3 seconds
  -o clean_results.json -of json

# Most common enterprise false positive scenario:
# App returns 200 for everything with custom "Page Not Found" content
# Solution: -fs [size_of_custom_404_page]

# Find the custom 404 size:
curl -so /dev/null -w "%{size_download}" \
  "https://app.company.com/definitely_does_not_exist_xyz123"
# Returns: 2847 → use -fs 2847 in your ffuf command
```

---

## 🔁 ffuf in Burp Proxy Mode

```bash
# Route all ffuf traffic through Burp for evidence capture:
ffuf -u https://app.company.com/FUZZ \
  -w raft-medium-directories.txt \
  -x http://127.0.0.1:8080 \
  -mc 200,401,403 \
  -o ffuf_burp.json

# This means:
# → Every ffuf request visible in Burp HTTP History
# → Interesting responses can be sent to Repeater with 1 click
# → Complete evidence trail in Burp project file
# → Easy to follow up on discovered endpoints immediately
```

---

## 📊 Processing ffuf JSON Output

```bash
# Parse JSON output for clean results:
cat ffuf_results.json | jq '.results[] | "\(.status) \(.length) \(.url)"'

# Extract only 200 responses:
cat ffuf_results.json | jq '.results[] | select(.status == 200) | .url'

# Find largest responses (most content = most interesting):
cat ffuf_results.json | jq '.results | sort_by(.length) | reverse | .[0:10] | .[] | "\(.length) \(.url)"'

# Extract URLs for further testing:
cat ffuf_results.json | jq -r '.results[].url' > discovered_urls.txt
```

---

## 📋 Enterprise Report — ffuf Evidence

```
Finding: API Endpoint Discovered — Unauthenticated Admin Function

Discovery command:
  ffuf -u https://api.company.com/api/v1/FUZZ \
    -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
    -H "Authorization: Bearer STANDARD_USER_TOKEN" \
    -mc 200,401,403 \
    -fs 45

Output (relevant line):
  [Status: 200, Size: 3821, Words: 142, Lines: 89]
  https://api.company.com/api/v1/admin-export

Manual verification:
  curl -s "https://api.company.com/api/v1/admin-export" \
    -H "Authorization: Bearer STANDARD_USER_TOKEN" | jq .
  → Returns complete user database export accessible to standard user

Finding: Broken Function Level Authorization — /api/v1/admin-export
Severity: Critical
```

---

## 🧭 Key Takeaways

**1. Size-based filtering is the difference between useful and useless results.**
Without `-fs`, ffuf output on enterprise apps is full of false positives — every path returns 200 with a custom "not found" page. Find the custom 404 size with one curl command, add `-fs [that_size]`, and your results are clean.

**2. POST body and JSON fuzzing is where ffuf beats every other content discovery tool.**
No other content discovery tool handles JSON body fuzzing as cleanly as ffuf. The `-d '{"FUZZ": "test"}'` pattern for mass assignment discovery is uniquely effective and not easily replicated in Gobuster or Dirsearch.

**3. Route ffuf through Burp proxy — always.**
`-x http://127.0.0.1:8080` adds all ffuf traffic to Burp HTTP History. When ffuf discovers `/api/v1/admin-export`, you can immediately right-click → Send to Repeater and start testing it. No need to reconstruct the request.

**4. JSON output enables programmatic analysis.**
`-of json` creates a structured output file. Parse it with `jq` to sort by response size, filter by status code, or extract URLs for the next phase of testing. This is the difference between looking at a wall of text and having actionable data.

---

## 🔗 References
- [ffuf GitHub](https://github.com/ffuf/ffuf)
- [ffuf Wiki](https://github.com/ffuf/ffuf/wiki)
- [SecLists Wordlists](https://github.com/danielmiessler/SecLists)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>

