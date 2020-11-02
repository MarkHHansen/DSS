package main

import (
	"aestofile"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"rsacustom"
)

// Main
func main() {
	fmt.Println("Test for task 1: ")
	TestRSA()

	fmt.Println("Test for task 2: ")
	TestAES()

	// Infinite loop
	for true {
	}
}

// TestAES tests EncrypToFile() and EncryptToFile() functions
func TestAES() {
	// Generate public and private key
	public, private, err := rsacustom.KeyGen(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create size of random message to encrypt
	size := big.NewInt(128)
	msgEncrypt, _ := rand.Int(rand.Reader, size)
	fmt.Print("Encrypt messsage:	")
	fmt.Println(msgEncrypt)

	// Encrypt message to a cipher text
	c := rsacustom.Encrypt(public, msgEncrypt)
	fmt.Print("Cipher text:		")
	fmt.Println(c)

	// Decrypt cipher text
	msgDecrypt := rsacustom.Decrypt(private, c)
	fmt.Print("Decrypted message:	")
	fmt.Println(msgDecrypt)
	fmt.Print("\n")

	//Generate a random 32 byte key for AES
	bytes := make([]byte, 32)
	_, err = rand.Read(bytes)
	if err != nil {
		panic(err)
	}

	//Encode key in bytes to string
	AESKey := hex.EncodeToString(bytes)
	fmt.Println("AESKey used to encrypt/decrypt: " + AESKey)

	// Encrypt the RSAPrivateKey to a cipher text and place it in "aes.txt"
	RSAPrivateKey := fmt.Sprintf("%s", private.D)
	encrypted := aestofile.EncryptToFile(RSAPrivateKey, AESKey)
	fmt.Println("Encrypted (Cipher text): " + encrypted)

	// Decrypt the RSAPrivateKey from "aes.txt" and print it on the console
	decrypted := aestofile.DecryptToFile(AESKey, "aes.txt")
	fmt.Println("Decrypted cipher text (RSAPrivateKey): " + decrypted)

	// Convert RSAPrivateKey from string to big.int
	temp := new(big.Int)
	temp.SetString(decrypted, 10)

	// Create new key object with the key from "aes.txt"
	privateKeyFromTxtFile := &rsacustom.PrivateKey{N: private.N, D: temp}

	// Try to decrypt the cipher text created by Encrypt() with the key found in "aes.txt"
	msgDecryptOld := rsacustom.Decrypt(privateKeyFromTxtFile, c)
	fmt.Print("Decrypted message:	")
	fmt.Println(msgDecryptOld)

}

//TestRSA tests the RSA KeyGen(), Encrypt() and Decrypt() functions
func TestRSA() {

	for i := 0; i < 5; i++ {
		public, private, err := rsacustom.KeyGen(128)

		if err != nil {
			fmt.Println(err)
			return
		}
		size := big.NewInt(128)
		msgEncrypt, _ := rand.Int(rand.Reader, size)
		fmt.Print("Encrypt messsage:	")
		fmt.Println(msgEncrypt)

		c := rsacustom.Encrypt(public, msgEncrypt)
		fmt.Print("Cipher text:		")
		fmt.Println(c)

		msgDecrypt := rsacustom.Decrypt(private, c)
		fmt.Print("Decrypted message:	")
		fmt.Println(msgDecrypt)

		fmt.Print("\n")
	}

}
