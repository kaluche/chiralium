# chiralium
## Description
Just a simple tool to generate binary from shellcode with Golang. Of course, you need to be able to "go build". You can also either specify your own shellcode or use msfvenom to generate a meterpreter reverse_https (x86 or x64) on the fly. In order to avoid static shellcode detection, the shellcode is stored encrypt with AES (unique random key / iv are generate at each compilation) in the go file, and next compiled and decrypted on execution. A resource file for metasploit is also created, because i'm too lazy to run it manually. I take no credit for anything, just using stuff from many places.

At this moment, you can :
- only compile windows shellcode
- compile for x86 or x64 architecture
- execute your shellcode with a syscall

This program was test on Linux and python3.

## Installation
Components required :
- golang
- python3

Optional components :
- metasploit 

Install python3 packages
```
$ sudo apt-get install git wget python3 python3-pip
```

 Install requirements
```
$ git clone https://github.com/kaluche/chiralium
$ cd chiralium
$ pip3 install -r requirements.txt
```

Install go (see here for details https://golang.org/doc/install or just search...it's easy).
```
$ wget https://dl.google.com/go/go1.13.5.linux-amd64.tar.gz
$ sudo tar -C /usr/local -xzf go1.13.5.linux-amd64.tar.gz
$ export PATH=$PATH:/usr/local/go/bin
(to be persistent, add it to your $HOME/.profile )
$ go version
go version go1.13.5 linux/amd64
$ python3 chiralium.py -t # should be good
```


## Usage 

### First launch
At the first launch, chiralium create missing directory and files.

[SCREENSHOT FIRST LAUNCH]

### Test mode

Before anything, it's recommended to "test" that everything works with --test / -t. Shellcode inside shellcode/calc.hex will be used. It's juste a "windows/exec cmd=calc.exe" but if you don't trust me (I understand :D), put the shellcode you want inside this file.

[SCREENSHOT TEST] 

### Compile shellcode from file

You need to specify a shellcode that will be compiled inside the "output" directory in chiralium. It uses the "src/main.go" to add your shellcode, encrypted with AES. Valid option are : 
- -sc / --shellcode : the path to your shellcode (need to be in hex)
- -o / --output : the name of your binary (default is random)
- -a / --arch : the architecture you want : x86 or x64

[SCREENSHOT SHELLCODE CUSTOSM COMPILATION] 

### Compile shellcode from msfvenom

You can also use msfvenom to generate a meterpreter (reverse_https only ATM) on the fly. The shellcode will be stored in the "shellcode/" directory of chiralium. Of course, you must specify your LHOST. Default LPORT is 8443. If you want, you can add "-rc/--rc" to run msfconsole with the associated resource file. (It will run with your current user). Valids options are :
- -msf / --msfvenom : use msf
- -lhost / --lhost : your IP
- -lport / --lport : your PORT
- -rc / --rc : run the resource file in msfconsole with your current user (obviously, it won't work as non-privileged user on port 1024)

[SCREENSHOT SHELLCODE MSF / RC] 