# John the Ripper — Enterprise Penetration Testing Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Tool Mastery — Password Hash Cracking & Password Policy Auditing
>
> **Context:** John the Ripper (JtR) complements Hashcat in enterprise testing. Where Hashcat excels at GPU-accelerated cracking, John excels at auto-detecting hash formats, cracking common file-based password hashes (ZIP, PDF, SSH keys), and running on CPU where GPU is unavailable. I use John most frequently in enterprise engagements for cracking protected files found during testing and for auditing Linux system password files when internal system access is in scope.

---

## 🔧 Core Usage in Enterprise Testing

### Auto-Detection and Basic Cracking

```bash
# John auto-detects hash format — often no mode specification needed
john hashes.txt
# Tries common formats automatically

# Specify wordlist (otherwise uses built-in mangled words):
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Show cracked passwords:
john --show hashes.txt

# List supported formats:
john --list=formats | grep -i "md5\|sha\|bcrypt\|ntlm"
```

### Linux System Password Auditing

```bash
# When /etc/passwd and /etc/shadow are accessible (internal assessment):
# Combine the files for John:
unshadow /etc/passwd /etc/shadow > combined.txt

# Crack with wordlist:
john --wordlist=/usr/share/wordlists/rockyou.txt combined.txt

# With rules:
john --wordlist=/usr/share/wordlists/rockyou.txt \
  --rules=best64 \
  combined.txt

# Show results:
john --show combined.txt

# Enterprise context:
# Finding: Path traversal exposed /etc/shadow
# Action: Demonstrate crackability of weak passwords
# Evidence: john --show output with cracked passwords
```

### Windows NTLM Hash Cracking

```bash
# NTLM hashes from Windows SAM database or network capture:
# Format: username:UID:LM_HASH:NT_HASH:::

cat > ntlm_hashes.txt << 'EOF'
administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
EOF

john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ntlm_hashes.txt
john --format=NT --show ntlm_hashes.txt
```

---

## 📁 File Password Cracking — High Value in Enterprise Testing

This is where John provides unique value not easily replicated by Hashcat in quick engagement scenarios.

### Protected ZIP Files

```bash
# Found a password-protected ZIP during directory enumeration or path traversal
# e.g., /backup/database_backup.zip found in web root with password protection

# Extract hash from ZIP:
zip2john backup.zip > zip_hash.txt

# Crack the hash:
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
john --wordlist=targeted_list.txt zip_hash.txt

# Show result:
john --show zip_hash.txt

# Enterprise finding value:
# "Encrypted ZIP found at /backup/database_backup.zip
# Password cracked in X seconds — file contains database dump with credentials"
```

### Protected PDF Files

```bash
# PDF files with password protection found during testing:
pdf2john protected_document.pdf > pdf_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash.txt
john --show pdf_hash.txt
```

### Encrypted SSH Private Keys

```bash
# SSH private key found via path traversal — has passphrase protection:
ssh2john id_rsa > ssh_key_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_key_hash.txt
john --show ssh_key_hash.txt

# If cracked: private key passphrase recovered
# ssh -i id_rsa user@target  (now usable)
# Enterprise impact: server access via stolen private key
```

### Other File Types

```bash
# Microsoft Office files (Word, Excel with password):
office2john protected.docx > office_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt office_hash.txt

# KeePass password database:
keepass2john Database.kdbx > keepass_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt keepass_hash.txt
# Enterprise impact: entire password vault accessible if cracked
```

---

## 🔧 Rules and Wordlist Enhancement

```bash
# John built-in rules:
john --wordlist=rockyou.txt --rules=best64 hashes.txt
john --wordlist=rockyou.txt --rules=jumbo hashes.txt

# Custom enterprise-targeted wordlist generation:
cat > company_words.txt << 'EOF'
Company
Welcome
Password
Admin
Summer
Winter
Spring
Autumn
Info
EOF

# Generate mutations from base words:
john --wordlist=company_words.txt --rules --stdout > mutated_list.txt
# Produces: Info1, Info!, Info@2024, info, INFO...

# Use mutated list with hashcat for GPU speed:
hashcat -a 0 -m 0 hashes.txt mutated_list.txt
```

---

## 📋 Enterprise Report Template

```
Finding Title: Protected Backup File Password Cracked — Database Credentials Exposed

Severity: Critical | CVSS: 9.1

Discovery chain:
  1. Directory enumeration found /backup/ directory accessible without auth
  2. /backup/database_export_2024.zip downloaded (password protected)
  3. zip2john extracted hash from ZIP
  4. john cracked password in 3 minutes using rockyou.txt

Evidence:
  zip2john database_export_2024.zip > zip_hash.txt
  john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt

  Result: database_export_2024.zip:company2024

  ZIP contents after extraction:
  - users_export.sql (50,000 user records with bcrypt hashes)
  - config.sql (database credentials for all environments)
  - prod_connection.txt (production DB connection string with password)

Impact:
  Production database credentials exposed. All user password hashes
  accessible for offline cracking. Complete data breach scenario confirmed.

Remediation:
  Remove /backup/ directory from web root immediately
  If backups must be web-accessible: require authentication + IP allowlist
  Use strong random passwords for archive encryption (not company name)
  Implement monitoring for bulk file access from web directories
```

---

## 🧭 Key Takeaways

**1. The `*2john` utilities are John's unique strength — use them for file cracking.**
`zip2john`, `ssh2john`, `pdf2john`, `keepass2john` — these extract crackable hashes from protected files that Hashcat cannot handle directly. Finding a password-protected backup file and cracking it is often the most impactful demonstration in an enterprise assessment.

**2. John auto-detects hash formats — useful when format is unknown.**
When you extract hashes from a database and are unsure of the exact format, `john hashes.txt` without specifying format lets John attempt identification. Once it identifies the format, use `john --format=identified_format --wordlist=list.txt hashes.txt` for the targeted run.

**3. Combine John for file extraction with Hashcat for GPU cracking.**
Extract the hash with John's utilities, then crack with Hashcat for maximum speed. `zip2john file.zip > hash.txt` → `hashcat -m 13600 hash.txt wordlist.txt`. Best of both tools.

**4. KeePass database cracking has the highest enterprise impact.**
If a KeePass `.kdbx` file appears anywhere in the engagement — server filesystem, backup archive, developer machine — `keepass2john` extracts a crackable hash. If the master password is weak, the entire enterprise credential vault is compromised. Always test KeePass files when found.

---

## 🔗 References
- [John the Ripper Documentation](https://www.openwall.com/john/doc/)
- [John the Ripper GitHub](https://github.com/openwall/john)
- [SecLists Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
