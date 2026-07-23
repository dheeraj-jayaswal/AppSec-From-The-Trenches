# API Security Testing — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — OWASP API Security Top 10
>
> **Tools:** Burp Suite, Postman, ffuf, Nuclei
>
> **Real-world impact:** API security is where I find the most high-severity findings in modern enterprise applications. Every enterprise application built in the last five years is API-first — the frontend is a JavaScript shell, and all the real logic, data, and access control lives in the API. The shift to microservices means there are dozens of internal APIs, many of which were built by different teams with different security standards, and few of which received the same security review attention as the user-facing application.

---

## 🧠 Why API Testing Is Different From Web App Testing

```
Traditional web app testing:
  Browser → HTML forms → Server → HTML response
  Attack surface: form fields, URL parameters, cookies

Modern enterprise API testing:
  SPA → REST/GraphQL API → Microservices → Database
  Attack surface: JSON bodies, HTTP methods, auth headers,
                  API versioning, inter-service trust, mass assignment

Key differences:
  APIs return JSON, not HTML → no XSS via form fields
  APIs have machine-to-machine auth → different token handling
  APIs have versioning → old versions may have less security
  APIs have different rate limiting → often less than web
  APIs often lack WAF coverage → direct access to vulnerabilities
  APIs trust other services internally → SSRF to internal APIs
```

---

## 🔍 Phase 1 — API Discovery

Before testing, map the complete API surface.

```
Source 1 — OpenAPI/Swagger documentation (if available):
  /swagger-ui.html
  /swagger-ui/index.html
  /api/swagger-ui.html
  /v2/api-docs            → JSON spec
  /v3/api-docs            → OpenAPI 3.0 spec
  /openapi.json
  /api/openapi.yaml

  If found: download the spec file
  → All endpoints, parameters, expected request formats are documented
  → Import into Postman for structured testing

Source 2 — GraphQL introspection:
  POST /graphql
  Body: {"query": "{ __schema { types { name fields { name } } } }"}
  → Returns complete API schema (types, fields, mutations, queries)
  → Import into InQL Burp extension for visual schema exploration

Source 3 — JavaScript bundle analysis (most reliable for undocumented APIs):
  Burp → HTTP History → filter by .js extension
  Install JS Miner extension → automatically extracts API endpoints
  Or manually: search JS files for: fetch(, axios., /api/, endpoint:

Source 4 — Traffic analysis (browse app with Burp intercepting):
  Use the application as a real user for 30 minutes
  Every action (login, search, view, update, export) generates API calls
  HTTP History shows the real API surface → most reliable

Source 5 — API version discovery via ffuf:
  ffuf -u https://app.company.com/FUZZ/users \
    -w versions.txt -mc 200,401
  
  versions.txt content:
    api
    api/v1
    api/v2
    api/v3
    api/latest
    v1
    v2
    internal
```

---

## 💥 Phase 2 — OWASP API Security Top 10 Testing

### API1 — Broken Object Level Authorization (BOLA/IDOR)

The most common and highest-impact API vulnerability.

```
Test: Change object IDs in API requests
  GET /api/v1/users/1099/profile → your data
  GET /api/v1/users/1042/profile → another user's data?

  POST /api/v1/orders/88234/cancel → cancels your order
  POST /api/v1/orders/88233/cancel → cancels another user's order?

Test with Burp Autorize:
  Setup Autorize with victim user's Authorization header
  Browse as admin → Autorize replays each request as victim
  "Bypassed!" in green = BOLA confirmed

Test all objects: users, orders, invoices, documents, tickets, reports
```

### API2 — Broken Authentication

```
Test: Can you call API endpoints without a token?
  Remove Authorization header entirely
  Replace with empty: Authorization: Bearer
  Replace with expired token from previous session

Test: Token scope — does one user's token work on another user's resources?
  Collect token from User A
  Use it to access User B's resources
  If successful = token has no user binding = Broken Auth

Test: API key in URL parameters:
  GET /api/reports?api_key=abc123
  → Key in URL = logged in server logs, proxy logs, browser history
  = Information disclosure finding
```

### API3 — Broken Object Property Level Authorization (Mass Assignment)

```
Test: Add undocumented fields to POST/PUT/PATCH requests
  Normal request:
  PUT /api/users/profile
  {"name": "Dheeraj", "phone": "9201734341"}

  Attack:
  PUT /api/users/profile
  {"name": "Dheeraj", "phone": "9201734341",
   "role": "admin",
   "is_verified": true,
   "subscription_plan": "enterprise",
   "credit_balance": 99999,
   "account_type": "premium"}

  Compare response → any new fields reflected back?
  Check profile API → do any new fields appear?
  → Accepted field = Mass Assignment = privilege escalation

Find candidate fields:
  Review GET /api/users/me response for all fields
  Any field in the response is a candidate for injection in PUT
  Especially: role, is_admin, plan, credits, verified, internal_notes
```

### API4 — Unrestricted Resource Consumption

```
Test: Rate limiting on authentication endpoints
  POST /api/auth/login — 50 rapid requests — any lockout?
  POST /api/auth/verify-otp — 1000 requests — any throttle?

Test: Resource-intensive operations
  POST /api/reports/generate → large dataset, slow operation
  → No rate limiting + expensive operation = DoS vector

Test: File upload size limits
  Upload a large file (100MB) → any file size limit enforced?
  Upload 1000 small files rapidly → rate limited?

In Burp Intruder:
  Set null payload (no modification)
  Send 100+ requests → watch response time/status
  Any change in response after N requests = rate limiting exists
  Constant 200 responses = no rate limiting
```

### API5 — Broken Function Level Authorization

```
Test: Access admin API functions with standard user token

Discovery:
  Find admin endpoints from Swagger spec, JS source, Nikto, directory enum
  /api/admin/users         → list all users
  /api/admin/config        → application configuration
  /api/admin/export        → export all data
  /api/internal/metrics    → application metrics
  /api/v1/users/bulk       → bulk operations

Test: Send standard user's Bearer token to each admin endpoint
  GET /api/admin/users HTTP/1.1
  Authorization: Bearer <standard_user_token>

  If 200 = Vertical privilege escalation = Critical
  If 403 = Correctly protected
  If 404 = Endpoint does not exist (or hidden differently)

HTTP method override:
  Some APIs accept method overrides:
  POST /api/admin/users HTTP/1.1
  X-HTTP-Method-Override: GET
  → Bypasses method-based access controls
```

### API6 — Unrestricted Access to Sensitive Business Flows

```
Test: Can you bypass business logic through API manipulation?

Example — quantity manipulation:
  POST /api/cart/add
  {"product_id": 123, "quantity": 1}  → normal
  {"product_id": 123, "quantity": -100}  → negative quantity = credit?
  {"product_id": 123, "quantity": 0}    → free item?

Example — price manipulation:
  POST /api/checkout
  {"cart_id": 456, "discount_code": "SAVE10"}  → normal
  {"cart_id": 456, "discount_code": "SAVE10", "final_price": 0.01}
  → Does backend accept client-supplied final price?

Example — workflow bypass:
  Normal flow: Step1 → Step2 → Step3 → Confirm
  Skip directly to Confirm with parameters from Step3
  → API may not validate that Step1 and Step2 were completed

Race condition:
  Redeem coupon code once → successful
  Send 5 rapid requests simultaneously to redeem same code
  → Race condition may allow multiple redemptions
  Use Turbo Intruder in Burp for race condition testing
```

---

## 🔧 Phase 3 — Postman for API Security Testing

```
Setup for enterprise API testing:

1. Import API spec:
   File → Import → OpenAPI spec file (swagger.json / openapi.yaml)
   → All endpoints populated automatically with example requests

2. Environment configuration:
   Variables: {{base_url}}, {{auth_token}}, {{user_id_victim}}
   → Switch between user roles by changing auth_token variable

3. Authentication setup:
   Collection → Authorization → Bearer Token: {{auth_token}}
   → Applied to all requests in collection automatically

4. Pre-request scripts for automated auth:
   pm.environment.set("auth_token", "eyJhbGciOiJIUzI1NiJ9...");

5. Test scripts for automated BOLA testing:
   pm.test("BOLA check - should not return other user's data", function() {
     var jsonData = pm.response.json();
     pm.expect(jsonData.user_id).to.not.equal(victim_user_id);
   });

6. Collection Runner for batch testing:
   Run → select collection → Run Collection
   → Tests all endpoints systematically
   → Exports CSV/JSON report of results

Postman vs Burp for API testing:
  Postman: structured testing, documentation-driven, collection runs
  Burp:    manual manipulation, intercepting live traffic, fuzzing
  → Use both: Postman for systematic coverage, Burp for deep manual testing
```

---

## 🔧 Phase 4 — GraphQL Security Testing

```
Step 1 — Enable introspection (if not already done):
  POST /graphql
  {"query": "{ __schema { types { name } } }"}
  If returns types = introspection enabled = full schema available

  Full schema dump:
  {"query":"{ __schema { queryType { name } mutationType { name }
   types { name kind description fields { name type { name kind } }
   inputFields { name } } } }"}

Step 2 — Find sensitive queries:
  Look for: getUser, getUserById, getAllUsers, adminUsers
  Look for: deleteUser, promoteUser, updatePermissions

Step 3 — Test authorization on each query:
  Standard user token → send admin-level query
  query { getAllUsers { id email password_hash salary } }
  → If returns data = Broken Function Level Authorization

Step 4 — Batching attacks (DoS or bypass rate limits):
  Send many queries in a single request:
  [
    {"query": "{user(id:1){email}}"},
    {"query": "{user(id:2){email}}"},
    ...repeat 100 times...
  ]
  → Bypasses per-request rate limiting
  → Can enumerate 100 user records in a single HTTP request

Step 5 — SSRF via URL arguments:
  mutation { fetchExternalResource(url: "http://169.254.169.254/") }
  → If resolver makes HTTP request = SSRF via GraphQL

Burp extension: InQL — visualises GraphQL schema, generates test queries
```

---

## 🗂️ Systematic API Testing Checklist

```
DISCOVERY
☐ Find Swagger/OpenAPI spec — import into Postman
☐ Check for GraphQL endpoint + introspection
☐ Extract API endpoints from JS bundles (JS Miner)
☐ Enumerate API versions: /v1/, /v2/, /internal/, /api/

AUTHENTICATION
☐ Test endpoints without any Authorization header
☐ Test with expired token
☐ Test with token from a deleted account
☐ Check API key in URL parameters → information disclosure

AUTHORIZATION (BOLA)
☐ Set up two user accounts (attacker + victim)
☐ Test all object IDs with attacker's token
☐ Configure Autorize in Burp for automated BOLA detection
☐ Test HTTP methods: GET/PUT/DELETE/PATCH on each resource

MASS ASSIGNMENT
☐ Add privileged fields to every POST/PUT request
☐ Compare GET response fields vs PUT accepted fields
☐ Test: role, is_admin, plan, credits, verified fields

RATE LIMITING
☐ Test auth endpoints: 50 rapid login attempts
☐ Test OTP verification: rapid sequential attempts
☐ Test export/report generation: concurrent requests
☐ Test resource-intensive operations for throttling

GRAPHQL SPECIFIC
☐ Check introspection enabled
☐ Test batching attack (100 queries in one request)
☐ Test admin-level queries with standard user token
☐ Check for SSRF via URL arguments in mutations
```

---

## 🧭 Key Takeaways

**1. BOLA is the most common Critical finding in API-first enterprise apps.**
Every API endpoint that returns or modifies a resource identified by an ID is a potential BOLA target. The Autorize extension in Burp makes systematic BOLA testing automated — configure it once, browse the application, and it flags every access control failure automatically.

**2. Import the OpenAPI spec before doing anything else.**
If the application has a Swagger or OpenAPI spec, importing it into Postman gives you a complete, structured list of every endpoint and parameter in minutes. This is dramatically more efficient than reconstructing the API surface from traffic alone.

**3. Mass assignment is easy to overlook and frequently Critical.**
Developers build a POST endpoint, document 3 fields, but the underlying ORM accepts all fields. Test every update endpoint by adding privilege fields (role, is_admin, plan) from the GET response. If any field is accepted and reflected back, it is a Critical privilege escalation finding.

**4. Test old API versions — they are almost always less secure.**
`/api/v2/` may have proper auth checks. `/api/v1/` — which was supposed to be retired but still responds — may not. Certificate transparency and directory enumeration often surface old API version paths. Always test them.

**5. GraphQL introspection enabled in production is an immediate finding.**
Introspection gives the attacker the complete API schema — every query, mutation, and type. For an internal enterprise application, this is equivalent to handing an attacker the full database schema and all available operations. Document it as an information disclosure finding and test every query for authorization bypass.

---

## 🔗 References
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger API Testing Guide](https://portswigger.net/web-security/api-testing)
- [Postman API Testing Documentation](https://learning.postman.com/docs/designing-and-developing-your-api/testing-an-api/)
- [InQL Burp Extension](https://github.com/doyensec/inql)

---
<div align="center">

*Part of [AppSec From The Trenches](README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
