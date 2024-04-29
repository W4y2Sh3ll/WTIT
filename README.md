# WTIT
WTIT is a Automatic Exploitation Generation tool aim at CTF-Pwn. This tool can detect stack overflow vulnerability in x86 64-bit binary. And if possible it will generate a payload file or pwncli script by using the detected vulnerabilities to exploit the binary.
WTIT is only able to finish exploitation of ret2backdoor, ret2shellcode and ret2libc

## Requirements:
- angr==9.2.76
- python 3.10
- radare2
- pwntools
- pwncli
- ROPGadget
## Installation:
``` shell
git clone https://github.com/W4y2Sh3ll/WTIT.git
```

## Usage
``` shell
./main.py binary_path
```