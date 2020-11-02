package main

import (
	// Custom Package
	"fmt"
	"math/big"
	"rsacustom"
	"strings"
	// Custom Package
)

// Main
func main() {
	fmt.Println("Test program started. ")
	// Infinite loop
	for true {
		fmt.Println("Push 1 for automatic test, push two for manual: ")
		mode := ""
		fmt.Scan(&mode)
		if mode == "1" {
			AutoTestNormal()
		} else {
			fmt.Println("First choose a filename: ")
			fname := ""
			fmt.Scan(&fname)

			fmt.Println("Now choose password. Passwords ahve to be either 16 or 32 charactes long. ")
			pswd := ""
			fmt.Scan(&pswd)

			if len(pswd) != 16 || len(pswd) != 32 {
				fmt.Println("Incorrect amount of characters! ")
				continue
			}
			pubkeyString := rsacustom.Generate(fname, pswd)
			pubKey := new(rsacustom.PublicKey)
			stringArr := strings.Split(pubkeyString, ",")
			pubKey.N, _ = new(big.Int).SetString(stringArr[1], 10)
			pubKey.E, _ = new(big.Int).SetString(stringArr[2], 10)

			fmt.Println("Now write the message to be signed, and it will be signed with the beforehand chosen filename and password: ")
			msgtoSign := ""
			fmt.Scan(&msgtoSign)
			byteMsg := []byte(msgtoSign)
			signMsg := rsacustom.Sign(fname, pswd, byteMsg)

			fmt.Println("The chosen message is verifyed: ")
			hashedMsg := rsacustom.Hash(new(big.Int).SetBytes(byteMsg))
			rsacustom.Verify(pubKey, signMsg, hashedMsg)
		}

	}
}

func AutoTestNormal() {
	fmt.Println("Generating a keypair with filename: GenerateTest and password: P4SSwordP4SSword. ")
	fname := "GenerateTest"
	pswd := "P4SSwordP4SSword"
	pubkeyString := rsacustom.Generate(fname, pswd)
	print("Public key from function: ")
	fmt.Println(pubkeyString)
	pubKey := new(rsacustom.PublicKey)
	stringArr := strings.Split(pubkeyString, ",")
	pubKey.N, _ = new(big.Int).SetString(stringArr[1], 10)
	pubKey.E, _ = new(big.Int).SetString(stringArr[2], 10)

	fmt.Println("Signing this message with the above specified details: \n This is a pretty fun exercise!")
	byteMsg := []byte("This is a pretty fun exercise!")
	signMsg := rsacustom.Sign(fname, pswd, byteMsg)

	fmt.Println("Veryfing the signinged message with the given public key. ")
	hashedMsg := rsacustom.Hash(new(big.Int).SetBytes(byteMsg))
	rsacustom.Verify(pubKey, signMsg, hashedMsg)
}

func AutoTestIncorrectPass() {

}
