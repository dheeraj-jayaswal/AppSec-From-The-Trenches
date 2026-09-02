# IDOR — Insecure Direct Object Reference — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Broken Access Control — OWASP A01:2021
>
> **Severity:** High to Critical — direct access to other users' data, actions, and resources
>
> **Real-world impact:** IDOR is one of the most consistently high-impact findings I document across enterprise engagements. Unlike many vulnerability classes, IDOR does not require clever exploitation or tool assistance — it requires understanding the application's data model and methodically testing whether access controls are enforced per object. In enterprise systems with tens of thousands of user records, a single IDOR finding can expose the entire dataset.

---

## 🧠 Why This Write-Up Exists

IDOR is fundamentally a trust problem. The application trusts the user's claimed object reference — an ID, a filename, a token — without verifying that the authenticated user is actually authorised to access that specific object.

In six years of enterprise testing, I have found IDOR in every category of application: HR systems exposing employee salary data, healthcare applications exposing patient records, financial platforms exposing account statements, and internal admin tools allowing any employee to modify any other employee's records. The common thread is always the same: the developer validated that the user was authenticated, but not whether the authenticated user owned the specific resource they were requesting.

The most damaging IDOR findings I have documented combined three elements: a sensitive data field (PII, financial data, credentials), a predictable or discoverable object reference (sequential integer IDs), and an unauthenticated or low-privilege access path. That combination means every record in the system is accessible to every attacker who creates one account.

---

## 📖 What Is IDOR?

IDOR occurs when an application uses user-controllable input to directly access an object — a database record, file, function, or action — without verifying that the requesting user has authorisation to access that specific object.

```
The IDOR access control gap:

Application correctly checks:  "Is the user authenticated?"      ✓
Application FAILS to check:    "Does this user OWN object #1042?" ✗

Request: GET /api/users/1042/profile
Server logic:
  1. Is user authenticated?              → Yes (valid session cookie)
  2. Does user own /users/1042?          → NOT CHECKED ← vulnerability
  3. Return profile data for user 1042   → Any user gets any profile

Correct server logic should be:
  1. Is user authenticated?              → Yes
  2. Get authenticated user ID from session → userId = 1099
  3. Does userId (1099) == requested ID (1042)?  → No → 403 Forbidden
```

---

## 🔍 Phase 1 — Reconnaissance: Mapping Object References

The quality of IDOR testing is directly proportional to how thoroughly you map object identifiers before you start testing.

### Types of Object References to Find

```
Category 1 — Numeric IDs (most common in enterprise .NET/Java apps):
  /api/users/1042
  /api/orders/88234
  /invoice/download/5523
  /ticket/9901
  /report/export/447
  /api/employees/EMP004421

Category 2 — GUIDs / UUIDs (require discovery):
  /api/documents/550e8400-e29b-41d4-a716-446655440000
  /files/download/6ba7b810-9dad-11d1-80b4-00c04fd430c8
  Appear random but are leaked in responses, emails, shared links

Category 3 — Hashed references (require discovery):
  /api/export/a94a8fe5ccb19ba61c4c0873d391e987
  /download?token=5f4dcc3b5aa765d61d8327de
  Appear secure — look for them in API responses and email links

Category 4 — Username / email-based:
  /api/users/john.smith/settings
  /profile/jsmith@company.com
  /reports?owner=john.smith

Category 5 — Indirect references in POST/PUT body:
  {"user_id": 1042, "action": "update"}
  {"account_id": "ACC-88234", "amount": 500}
  {"employee_id": "EMP004421", "field": "salary"}
```

### Where to Find Object References in Burp Suite

```
In HTTP History — look for IDs in:
  URL path:           /api/v2/invoices/§5523§
  Query parameters:   ?user_id=1042&format=pdf
  POST body (form):   account_id=88234&action=view
  POST body (JSON):   {"id":1042,"include":"full"}
  Response bodies:    {"user":{"id":1041,"email":"..."}}  ← harvest IDs
  Link headers:       Location: /api/users/1043
  Cookies:            user_ref=1042

Note ALL object IDs you encounter while browsing.
Every ID you see in a response is a potential IDOR test target.
```

---

## 💥 Phase 2 — Attack Vectors

### Vector 1 — Horizontal IDOR (Same Privilege, Different User)

The attacker accesses resources belonging to a different user with the same role. Most common, highest volume of findings.

**Methodology using two accounts:**

```
Setup: Create two test accounts
  Account A (Attacker):  attacker@test.com  → user_id = 1099
  Account B (Victim):    victim@test.com    → user_id = 1042

Step 1: Log in as Account B (Victim)
        Perform all application actions:
        - View profile → note URL: /api/users/1042/profile
        - Download invoice → note URL: /invoice/5523/download
        - View order → note URL: /api/orders/88234
        - Access messages → note URL: /api/messages/inbox/1042

Step 2: Log out of Account B
        Log in as Account A (Attacker)

Step 3: Access Account B's resources using Account A's session:

        GET /api/users/1042/profile
        Authorization: Bearer <Account A token>
        → Returns Account B's profile? = IDOR

        GET /invoice/5523/download
        Authorization: Bearer <Account A token>
        → Returns Account B's invoice? = IDOR

Step 4: Test all HTTP methods on IDOR endpoints:
        GET    /api/users/1042/profile  → read other user's data
        PUT    /api/users/1042/profile  → modify other user's data
        DELETE /api/users/1042          → delete other user's account
        PATCH  /api/users/1042/email    → change other user's email
```

> **Enterprise context:** In an HR application engagement, the employee profile endpoint `/api/employees/{id}` returned every field in the database including salary, performance rating, disciplinary notes, and bank account details for direct deposit. By incrementing the employee ID sequentially, I mapped and extracted data for all 4,200 employees in the organisation. The API had no pagination limit and no rate limiting. The entire HR database was accessible to any authenticated employee in approximately 10 minutes.

---

### Vector 2 — Vertical IDOR (Privilege Escalation)

A lower-privileged user accesses resources or performs actions reserved for administrators or higher-privileged roles.

```
Test standard user token against admin endpoints:

Discovery: Find admin endpoints by:
  → Checking robots.txt for /admin paths
  → Finding admin URLs in JS source code
  → Observing admin requests if you have legitimate admin test access

Test with standard user session:
  GET  /admin/users              → List all users with standard token
  GET  /admin/users/1042         → View any user's full details
  POST /admin/users/1099/promote → Promote yourself to admin
  GET  /admin/config/security    → View application security config
  POST /admin/api-keys/generate  → Create privileged API keys
  GET  /admin/audit-logs         → View all user activity logs

If any 200 response = Vertical IDOR = privilege escalation
```

**Mass Assignment — a specific form of vertical IDOR:**

```
When creating or updating a resource, test whether privileged
fields are accepted even though they should not be user-modifiable.

Normal profile update:
POST /api/users/1099/profile
Body: {"name": "Dheeraj", "phone": "9201734341"}
→ Standard fields — expected

Inject privileged fields:
POST /api/users/1099/profile
Body: {"name": "Dheeraj", "phone": "9201734341",
       "role": "admin",
       "is_verified": true,
       "subscription_tier": "enterprise",
       "credits": 99999}
→ If any privileged field is accepted = Mass Assignment = IDOR

Check the response: if role=admin appears in the updated profile
→ Critical privilege escalation finding
```

> **Enterprise context:** In a SaaS enterprise platform, the user registration endpoint accepted a `plan` field that was not in the UI form but was present in the API schema. Sending `{"plan": "enterprise"}` at registration gave the attacker account unlimited access to paid features. Discovered by comparing the registration request body against the full user object returned in the profile API response — the profile showed fields that the registration form never asked for.

---

### Vector 3 — GUID/UUID IDOR — Harvesting References

UUIDs appear unpredictable but are regularly leaked in places developers do not consider.

```
Where UUIDs get leaked in enterprise applications:

API responses:
  GET /api/users/me
  Response: {
    "id": "550e8400-e29b-41d4-a716-446655440000",    ← your UUID
    "team": {
      "members": [
        {"id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "name": "Alice"},
        {"id": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "name": "Bob"}
      ]
    }
  }
  → Team member UUIDs exposed → test each one

Shared link generation:
  POST /api/documents/share
  Response: {"share_link": "/doc/6ba7b810-.../view"}
  → UUIDs appear in share links → other documents use same UUID format

Email notifications:
  "Your invoice is ready: /invoice/550e8400-.../download"
  → If email is intercepted or forwarded, UUID is exposed

JS source files:
  const EXAMPLE_USER_ID = "550e8400-e29b-41d4-a716-446655440000";
  → Hardcoded example UUIDs point to real objects

Test methodology:
1. Collect every UUID you encounter in any response or URL
2. Test each UUID against other object types:
   /api/users/UUID  → /api/invoices/UUID  → /api/documents/UUID
3. Sometimes UUIDs are shared across object types (predictable namespace)
```

---

### Vector 4 — IDOR in File Downloads and Exports

File download and export endpoints are consistently the highest-severity IDOR findings because they combine access to multiple users' data in a single request.

```
Common enterprise file download IDOR patterns:

Direct filename reference:
  GET /download?file=user_1042_contract.pdf
  Test: GET /download?file=user_1043_contract.pdf
  → Returns another user's contract

Export endpoint with user reference:
  GET /api/reports/export?user_id=1042&format=csv
  Test: GET /api/reports/export?user_id=1043&format=csv
  → Returns another user's full data export

Invoice download:
  GET /invoice/5523/download
  Test: GET /invoice/5524/download   ← sequential
  → Another user's invoice

Bulk export (Critical):
  GET /api/admin/export/all-users
  → If accessible without admin role = all user data in one request

Filename manipulation for directory traversal chain:
  GET /download?file=../config/database.properties
  → Path traversal + IDOR combined = server file access
```

---

### Vector 5 — Second-Order IDOR

The object reference is stored at creation time and used in a different, less-protected endpoint later. The same pattern as second-order SQLi — harder to find, higher impact.

```
Pattern:
Step 1: User A registers with a referral code that stores their user_id internally
Step 2: A report or admin endpoint later uses that stored user_id to generate data
Step 3: If user_id is changeable after the fact via a profile update endpoint
        → user_id in the later endpoint changes too → IDOR in report generation

Another pattern:
Step 1: User creates a shared workspace → workspace_id = 447
Step 2: User A is the owner. Workspace stored with owner_id = 1042
Step 3: Profile update endpoint allows changing fields including a "workspace_owner" field
Step 4: Change workspace_owner to 1099 (attacker)
Step 5: Attacker now appears as owner of workspace 447 → accesses all workspace data

Why this matters:
Traditional IDOR testing changes the reference in the GET request.
Second-order IDOR manipulates stored references that affect later queries.
Automated scanners almost never find this.
```

---

## 🗂️ Phase 3 — Burp Suite IDOR Testing Workflow

```
Setup for two-account testing:

Step 1: Open two browser profiles (Chrome Profile 1 = Attacker, Profile 2 = Victim)
Step 2: Configure both to proxy through Burp Suite (different ports if needed)
        Or use Burp's built-in "New browser" feature for isolated sessions

Step 3: Log in as Victim in Profile 2
        → Enable Burp HTTP History logging
        → Perform EVERY action in the application
        → Note all object IDs, file names, tokens used

Step 4: Log in as Attacker in Profile 1
        → In Burp Repeater: change all Victim's object IDs one by one
        → Compare responses: same data = IDOR

Burp Intruder for scale testing:
        Capture: GET /api/invoice/§5523§
        Payload type: Numbers — From: 1, To: 10000, Step: 1
        Look for: Response Length change (different data)
                  Status code 200 vs 403
        Filter: Show only 200 responses = all accessible invoices

Burp Extension: Autorize
        Install from BApp Store
        Add Victim's cookie to Autorize config
        Browse as Admin → Autorize automatically re-tests each request
        with Victim's low-privilege cookie and flags authorisation bypasses
```

---

## 📋 Systematic Testing Checklist

```
HORIZONTAL IDOR
☐ Create two test accounts at same privilege level
☐ List all object IDs seen while browsing as Victim
☐ Access each ID using Attacker's session
☐ Test all HTTP methods: GET (read), PUT/PATCH (modify), DELETE (delete)
☐ Test file download endpoints with other users' file references

VERTICAL IDOR
☐ Identify admin endpoints from JS source, robots.txt, API docs
☐ Test each admin endpoint with standard user session token
☐ Test mass assignment: add role/is_admin/plan fields to update requests
☐ Check if API v1 admin endpoints are blocked but v2 are not

UUID/GUID IDOR
☐ Harvest all UUIDs from API responses
☐ Test each UUID against multiple endpoint types
☐ Check JS source files for hardcoded example UUIDs

EXPORTS AND DOWNLOADS
☐ Test all download/export endpoints with other users' IDs
☐ Check for sequential filenames in download URLs
☐ Test bulk export endpoints without admin role

SECOND-ORDER
☐ Map which fields are stored at creation vs fields used in later queries
☐ Test if stored IDs can be modified via profile/settings update
☐ Check if modified stored IDs affect data returned in reporting endpoints

PARAMETER LOCATIONS
☐ Test IDs in URL path: /users/§ID§
☐ Test IDs in query string: ?user_id=§ID§
☐ Test IDs in POST body (form): user_id=§ID§
☐ Test IDs in POST body (JSON): {"id":§ID§}
☐ Test IDs in custom headers: X-User-ID: §ID§
☐ Test IDs in cookies: user_ref=§ID§
```

---

## 📋 Enterprise Pentest Report Template

---

**Finding Title:** IDOR in Employee Profile API — Access to PII and Salary Data for All Employees

**Severity:** Critical

**CVSS v3.1 Score:** 8.6 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

**Affected Endpoint:** `GET /api/employees/{id}` | `PUT /api/employees/{id}/profile`

**Authentication Required:** Yes — Any standard employee account

---

**Vulnerability Description:**

The employee profile API endpoint does not verify that the authenticated user is authorised to access the specific employee record requested. Any authenticated employee can read and modify any other employee's profile, including name, salary, bank account details, national ID, performance ratings, and disciplinary history, by incrementing or enumerating the numeric employee ID parameter.

The PUT endpoint similarly lacks authorisation — any employee can overwrite any other employee's profile fields.

---

**Steps to Reproduce:**

1. Log in as Employee A (`user_id: 1099`)
2. View your own profile: `GET /api/employees/1099` — note the response fields
3. Change the ID to another employee: `GET /api/employees/1042`
4. Observe complete profile of Employee B is returned, including fields not shown in the UI
5. To demonstrate write access: `PUT /api/employees/1042` with body `{"salary": 0}` — confirms modification of another employee's record

---

**Proof of Concept:**

```
Request:
GET /api/employees/1042 HTTP/1.1
Host: hr.company.internal
Authorization: Bearer <Employee A token>

Response:
HTTP/1.1 200 OK
{
  "id": 1042,
  "name": "Jane Doe",
  "national_id": "XXXX-XXXX-7823",
  "salary": 88000,
  "bank_account": "HDFC-XXXXXX4521",
  "performance_rating": 3.2,
  "disciplinary_flag": true,
  "disciplinary_notes": "Written warning — Q2 2024"
}

Sequential enumeration test (Burp Intruder):
  IDs 1001 → 5200 returned 200 OK responses
  4,200 employee records fully accessible to any authenticated employee
```

---

**Business Impact:**

- Complete exposure of salary, bank account, and national ID data for all 4,200 employees
- GDPR violation — unauthorised access to personal data constitutes a reportable data breach
- Write access allows salary manipulation, performance record tampering, and disciplinary record modification
- No elevated privileges or special tools required — any employee with an account can execute this attack

---

**Remediation:**

| Priority | Action |
|---|---|
| Immediate | Add authorisation check: verify `authenticated_user_id == requested_employee_id` before returning data |
| Immediate | Apply check to all HTTP methods: GET, PUT, PATCH, DELETE |
| Immediate | Audit all API endpoints for missing ownership validation |
| Short-term | Implement a central authorisation middleware that enforces ownership checks across all resource endpoints |
| Short-term | Apply DTO mapping — return only fields the requesting user's role should see |
| Long-term | Add automated authorisation testing to CI/CD pipeline using tools like Autorize or custom test fixtures |

---

**Secure Code Pattern (C# / ASP.NET Core):**

```csharp
// ❌ VULNERABLE — no ownership check
[HttpGet("{id}")]
public async Task<IActionResult> GetEmployee(int id)
{
    var employee = await _repo.GetByIdAsync(id);
    return Ok(employee);  // returns any employee to any caller
}

// ✅ SECURE — ownership enforcement
[HttpGet("{id}")]
public async Task<IActionResult> GetEmployee(int id)
{
    // Extract the requesting user's ID from the JWT/session
    var requestingUserId = int.Parse(User.FindFirst("employee_id")?.Value);

    // Allow HR admins to access all records; others only their own
    bool isHrAdmin = User.IsInRole("HR_Admin");
    if (!isHrAdmin && id != requestingUserId)
        return Forbid();   // 403 — not 404 (avoid enumeration via status code)

    var employee = await _repo.GetByIdAsync(id);
    if (employee == null) return NotFound();

    // Return role-appropriate DTO (HR admin gets full data; employee gets limited view)
    if (isHrAdmin)
        return Ok(_mapper.Map<EmployeeFullDto>(employee));
    else
        return Ok(_mapper.Map<EmployeeSelfDto>(employee));
}
```

---

## 🧪 Practice Labs

| Platform | Resource | Focus Area |
|---|---|---|
| [PortSwigger Access Control Labs](https://portswigger.net/web-security/access-control) | 13 free labs | IDOR, vertical escalation, mass assignment |
| [HackTheBox Web Challenges](https://hackthebox.com) | API IDOR challenges | Real-world scenarios |
| [TryHackMe OWASP Top 10](https://tryhackme.com) | IDOR room | Beginner through intermediate |
| [DVWA](https://github.com/digininja/DVWA) | Access control module | Local testing environment |

---

## 🧭 Key Takeaways From 6+ Years of Enterprise Testing

**1. Authentication is not authorisation — enterprise developers confuse these constantly.**
Checking that the user is logged in is not the same as checking that the user owns the object they are requesting. I have seen this pattern fail in every enterprise engagement — the login check is always present, the ownership check is frequently absent. These are two separate problems that require two separate checks in every endpoint handler.

**2. Test ALL HTTP methods, not just GET.**
Most IDOR testing focuses on GET requests because those expose data. The most damaging IDOR findings involve PUT, PATCH, and DELETE — modifying or deleting another user's data. If GET /api/employees/1042 returns my data, PUT /api/employees/1042 might let me overwrite yours. Always test write and delete operations.

**3. Harvest object IDs from responses before you test endpoints.**
The best IDOR testing is systematic, not random. Before testing any endpoint, spend 20 minutes browsing the application and logging every object ID that appears in any API response. These are your test targets. The object IDs buried in API response fields — team members, related records, referenced objects — are often the ones most developers forget to protect.

**4. Mass assignment is a vertical IDOR hiding in plain sight.**
When you find an update endpoint, always add extra fields to the request body that are not in the UI form. Fields like `role`, `is_admin`, `plan`, `credits`, `subscription_tier`. Developers who correctly implement ownership checks often forget to whitelist accepted fields — accepting everything in the body and saving it all to the database. One field accepted = potential privilege escalation.

**5. IDOR findings scale with data sensitivity — report accordingly.**
IDOR exposing a username is low severity. IDOR exposing salary, national ID, or bank account data across 4,200 employee records is a Critical regulatory breach finding. Before writing the report, always answer: what is the most sensitive data accessible, and how many records are exposed? The numbers and data types determine the real business impact.

---

## 🔗 References

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP IDOR Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [PortSwigger Access Control Research](https://portswigger.net/web-security/access-control)
- [PayloadsAllTheThings — IDOR](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References)

---

<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
