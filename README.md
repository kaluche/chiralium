# chiralium
## Description
Just a simple tool to generate binary from shellcode with Golang. Of course, you need to be able to "go build". You can also either specify your own shellcode or use msfvenom to generate a meterpreter reverse_https (x86 or x64) on the fly. In order to avoid static shellcode detection, the shellcode is stored encrypt with AES (unique random key / iv are generate at each compilation) in the go file, and next compiled and decrypted on execution. A resource file for metasploit is also created, because i'm too lazy to run it manually.

This program was test on Linux and python3.

## Installation
[todo]

## Usage 
[todo]
