# Cyber-eto Qualifications 2025 - NoAuth CTF Challenge Writeup

## Challenge Description

**Challenge Name:** NoAuth  
**Category:** Network Forensics/DFIR  
**Flag Format:** `cybereto{attackerIP_victimIP_loginProtocol_username_password_fileName_fileContent}`

During a recent security incident, a suspicious network capture was obtained. Your task is to investigate the PCAP file, identify the malicious activity. Use your network forensics skills to extract the relevant information.

**Questions to Answer:**
- What is the IP of the attacker?
- What is the IP of the victim?
- Which protocol did the attacker use to log in to the victim machine?
- What username did the attacker use during login?
- What password did the attacker use to gain access?
- What is the name (including extension) of the file found on the victim machine?
- What is the content of that file?

## Initial Analysis

The challenge provides a PCAP file named `NoAuth.pcapng` containing network traffic from a security incident. Let's start by examining the file structure:

```bash
$ ls -la
total 392
drwxr-xr-x  3 laith  staff      96  1 تشرين الثاني 12:44 .
drwxr-xr-x  9 laith  staff     288  1 تشرين الثاني 12:44 ..
-rw-r--r--@ 1 laith  staff  198872  1 تشرين الثاني 12:44 NoAuth.pcapng
```

The PCAP file is approximately 194KB, suggesting a moderate amount of network traffic to analyze.

## Network Traffic Analysis

### Step 1: Protocol Hierarchy and Overview

First, let's get an overview of the network conversations and protocols:

```bash
$ tshark -r NoAuth.pcapng -q -z conv,ip
================================================================================
IPv4 Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.168.59.128       <-> 192.168.59.129          1030 62 kB        1056 61 kB        2086 124 kB       7٫622923007       41٫7774
192.168.59.1         <-> 192.168.59.255             0 0 bytes        36 2٬952 bytes      36 2٬952 bytes    0٫000000000       38٫4134
192.168.59.128       <-> 103.186.118.216            2 180 bytes       2 180 bytes       4 360 bytes    1٫760587562       31٫8031
192.168.59.128       <-> 192.168.59.2               1 142 bytes       1 87 bytes        2 229 bytes    7٫554607896        0٫0440
================================================================================
```

🎯 **Key Finding**: The main communication is between **192.168.59.128** and **192.168.59.129** with over 2000 frames (2086 total), indicating significant interaction between these two hosts.

Now let's examine the protocol hierarchy:

```bash
$ tshark -r NoAuth.pcapng -q -z io,phs
===================================================================
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:2134 bytes:128024
  ip                                     frames:2128 bytes:127718
    udp                                  frames:42 bytes:3541
      data                               frames:36 bytes:2952
      ntp                                frames:4 bytes:360
      dns                                frames:2 bytes:229
    tcp                                  frames:2086 bytes:124177
      ftp                                frames:30 bytes:2616
        ftp.current-working-directory    frames:30 bytes:2616
      ftp-data                           frames:2 bytes:225
        ftp-data.setup-frame             frames:2 bytes:225
          ftp-data.setup-method          frames:2 bytes:225
            ftp-data.command             frames:2 bytes:225
              ftp-data.command-frame     frames:2 bytes:225
                ftp-data.current-working-directory frames:2 bytes:225
                  data-text-lines        frames:2 bytes:225
  arp                                    frames:6 bytes:306
===================================================================
```

🎯 **Critical Discovery**: The traffic includes **FTP** protocol usage, which is commonly targeted for unauthorized access due to clear-text authentication.

### Step 2: Attack Pattern Recognition

Looking at the TCP traffic pattern, let's examine the initial connection attempts:

```bash
$ tshark -r NoAuth.pcapng -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" | head -20
    27 7.622923007 192.168.59.128 → 192.168.59.129 TCP 58 55688 → 995 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
    28 7.623168190 192.168.59.128 → 192.168.59.129 TCP 58 55688 → 143 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
    29 7.623283664 192.168.59.128 → 192.168.59.129 TCP 58 55688 → 23 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
    32 7.624751076 192.168.59.128 → 192.168.59.129 TCP 58 55688 → 21 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
    33 7.624803146 192.168.59.128 → 192.168.59.129 TCP 58 55688 → 113 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
    34 7.624878960 192.168.59.128 → 192.168.59.129 TCP 58 55688 → 3389 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
    35 7.624930917 192.168.59.128 → 192.168.59.129 TCP 58 55688 → 80 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
    # ... many more SYN packets to various ports
```

🚨 **Attack Pattern Identified**: This is a classic **port scan** from 192.168.59.128 targeting multiple services on 192.168.59.129:
- Port 995 (POP3S)
- Port 143 (IMAP)
- Port 23 (Telnet)
- Port 21 (FTP) ⭐
- Port 113 (Ident)
- Port 3389 (RDP)
- Port 80 (HTTP)
- And many others...

**Attacker**: 192.168.59.128  
**Victim**: 192.168.59.129

### Step 3: FTP Authentication Analysis

Let's examine the FTP traffic to extract authentication details:

```bash
$ tshark -r NoAuth.pcapng -Y "ftp" -T fields -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg -e ftp.response.code -e ftp.response.arg
192.168.59.129	192.168.59.128			220	(vsFTPd 2.3.4)
192.168.59.128	192.168.59.129	USER	anonymous		
192.168.59.129	192.168.59.128			331	Please specify the password.
192.168.59.128	192.168.59.129	PASS	anonymous		
192.168.59.129	192.168.59.128			230	Login successful.
192.168.59.128	192.168.59.129	SYST			
192.168.59.129	192.168.59.128			215	UNIX Type: L8
192.168.59.128	192.168.59.129	FEAT			
192.168.59.129	192.168.59.128			211	Features:
192.168.59.128	192.168.59.129	EPSV			
192.168.59.129	192.168.59.128			229	Entering Extended Passive Mode (|||33005|).
192.168.59.128	192.168.59.129	LIST			
192.168.59.129	192.168.59.128			150	Here comes the directory listing.
192.168.59.129	192.168.59.128			226	Directory send OK.
192.168.59.128	192.168.59.129	TYPE	I		
192.168.59.129	192.168.59.128			200	Switching to Binary mode.
192.168.59.128	192.168.59.129	SIZE	secret.txt		
192.168.59.129	192.168.59.128			213	25
192.168.59.128	192.168.59.129	EPSV			
192.168.59.129	192.168.59.128			229	Entering Extended Passive Mode (|||18988|).
192.168.59.128	192.168.59.129	RETR	secret.txt		
192.168.59.129	192.168.59.128			150	Opening BINARY mode data connection for secret.txt (25 bytes).
192.168.59.129	192.168.59.128			226	Transfer complete.
192.168.59.128	192.168.59.129	MDTM	secret.txt		
192.168.59.129	192.168.59.128			213	20250727195243
192.168.59.128	192.168.59.129	QUIT			
192.168.59.129	192.168.59.128			221	Goodbye.
```

🎯 **Authentication Extracted**:
- **Protocol**: FTP
- **Username**: anonymous
- **Password**: anonymous
- **Target File**: secret.txt (25 bytes)

### Step 4: File Content Recovery

The attacker successfully retrieved a file called `secret.txt`. Let's extract its contents from the FTP data transfer:

```bash
$ tshark -r NoAuth.pcapng -Y "ftp-data" -V | grep -A 10 -B 5 "secret"
[Setup method: EPASV]
[Command: RETR secret.txt]
Command frame: 2117
[Current working directory: ]
Line-based text data (1 lines)
    w1r3sh4rk_1s_4_g00d_t00l\n
```

🎯 **File Content Recovered**: `w1r3sh4rk_1s_4_g00d_t00l`

The content is a playful message acknowledging the use of Wireshark/tshark for network analysis.

## Attack Timeline Reconstruction

### Phase 1: Reconnaissance (Port Scanning)
- **Timestamp**: ~7.62 seconds from capture start
- **Action**: Attacker (192.168.59.128) conducts comprehensive port scan of victim (192.168.59.129)
- **Ports Scanned**: 995, 143, 23, 21, 113, 3389, 80, 8888, 3306, 8080, 443, 5900, 22, and many others
- **Result**: Discovered FTP service (port 21) responding with SYN-ACK

### Phase 2: Service Enumeration
- **Action**: Attacker connects to FTP service on port 21
- **Discovery**: vsFTPd 2.3.4 server identified
- **Result**: FTP service allows anonymous access

### Phase 3: Authentication
- **Method**: Anonymous FTP login
- **Credentials**: username=`anonymous`, password=`anonymous`
- **Result**: Successful authentication

### Phase 4: File Discovery and Exfiltration
- **Action**: Directory listing (`LIST` command)
- **Discovery**: File `secret.txt` (25 bytes)
- **Action**: File retrieval (`RETR secret.txt`)
- **Method**: Binary mode transfer over data channel (port 18988)
- **Result**: Successful exfiltration of sensitive file

## Vulnerability Analysis

### Critical Security Issues Identified:

1. **Anonymous FTP Access**: The victim server allows anonymous FTP access without proper authentication
2. **Sensitive File Exposure**: Critical files are accessible via anonymous FTP
3. **Clear-Text Protocol**: FTP transmits data in clear text, making it easily interceptable
4. **Inadequate Access Controls**: No restrictions on file access for anonymous users

### Attack Vectors Exploited:

1. **Network Reconnaissance**: Port scanning to identify services
2. **Service Exploitation**: Leveraging misconfigured anonymous FTP access
3. **Data Exfiltration**: Unauthorized file download

## Evidence Summary

| **Element** | **Value** |
|-------------|-----------|
| **Attacker IP** | 192.168.59.128 |
| **Victim IP** | 192.168.59.129 |
| **Attack Protocol** | FTP |
| **Authentication Method** | Anonymous |
| **Username** | anonymous |
| **Password** | anonymous |
| **Compromised File** | secret.txt |
| **File Content** | w1r3sh4rk_1s_4_g00d_t00l |
| **File Size** | 25 bytes |

## Final Flag

**Flag:** `cybereto{192.168.59.128_192.168.59.129_ftp_anonymous_anonymous_secret.txt_w1r3sh4rk_1s_4_g00d_t00l}`

## Key Lessons Learned

This incident demonstrates several critical security concepts:

1. **Anonymous FTP Risks**: Anonymous FTP access can lead to unauthorized data access and should be disabled unless absolutely necessary
2. **Network Monitoring**: Proper network monitoring can detect port scanning and suspicious connection patterns
3. **Protocol Security**: Clear-text protocols like FTP expose sensitive data during transmission
4. **Access Control**: Proper file permissions and access controls are essential to prevent unauthorized access

## Defensive Recommendations

### Immediate Actions:
1. **Disable Anonymous FTP**: Remove anonymous access to FTP services
2. **Implement Access Controls**: Restrict FTP access to authorized users only
3. **File System Hardening**: Remove sensitive files from FTP accessible directories
4. **Network Segmentation**: Isolate FTP services from critical network segments

### Long-term Security Measures:
1. **Protocol Upgrade**: Migrate from FTP to secure alternatives (SFTP, FTPS)
2. **Intrusion Detection**: Deploy IDS/IPS to detect port scanning and suspicious activities
3. **Regular Security Audits**: Conduct periodic reviews of service configurations
4. **Security Awareness**: Train staff on secure file sharing practices

## Tools and Techniques Used

- **Wireshark/tshark**: Primary analysis tool for PCAP examination
- **Protocol Analysis**: TCP stream following and FTP command extraction
- **Traffic Pattern Recognition**: Identifying port scanning behavior
- **Data Recovery**: Extracting file contents from FTP data transfers
- **Timeline Analysis**: Reconstructing attack sequence from packet timestamps

## Technical Indicators of Compromise (IOCs)

### Network IOCs:
- **Source IP**: 192.168.59.128 (scanning activity)
- **Target IP**: 192.168.59.129 (compromised FTP server)
- **Protocol**: FTP (TCP/21) with anonymous authentication
- **Behavioral Pattern**: Sequential port scanning followed by service exploitation

### File IOCs:
- **Accessed File**: secret.txt
- **File Size**: 25 bytes
- **Transfer Method**: FTP RETR command
- **Content Signature**: Contains string "w1r3sh4rk_1s_4_g00d_t00l"

This analysis demonstrates the importance of proper network security configuration and monitoring to prevent unauthorized access to sensitive systems and data.