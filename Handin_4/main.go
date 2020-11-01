package main

import (
	"aestofile" // Custom Package
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"rsacustom" // Custom Package
	"time"
)

// Main
func main() {
	//Testing the hashing of bits pr seconds
	TestHashBPS()

	//Testing the time of signing with a 2000 bit key
	TestSignatureTime()

	// fmt.Println("Test for task 1: ")
	// TestRSA()

	// fmt.Println("Test for task 2: ")
	// TestAES()

	// TestRSASignatures()

	// //Infinite loop
	for true {

	}
}

//TestHashBPS Testes the hashing speed
func TestHashBPS() {
	//Reads a file with 10kb = 80.000 bits
	c, _ := ioutil.ReadFile("bits.txt")

	hashMsg := new(big.Int).SetBytes(c)

	for true {
		start := time.Now()

		rsacustom.Hash(hashMsg)

		elapsed := time.Since(start)

		elapsedNano := elapsed.Nanoseconds()

		if elapsedNano != 0 {
			fmt.Print("Time of hashing the 80.000 bit message: ")
			fmt.Print(elapsedNano)
			fmt.Println(" ns")

			break
		}
	}

}

func TestSignatureTime() {
	_, private, _ := rsacustom.KeyGen(2000)

	size := big.NewInt(128)
	msgEncrypt, _ := rand.Int(rand.Reader, size)

	start := time.Now()
	rsacustom.Sign(private, msgEncrypt)
	elapsed := time.Since(start)

	fmt.Print("Time of signing with 2000 bit key: ")
	fmt.Print(elapsed.Nanoseconds())
	fmt.Println(" ns")

}

//TestRSASignatures makes a random message, hashes and signs it, and then verifies it.
func TestRSASignatures() {
	public, private, _ := rsacustom.KeyGen(256)

	size := big.NewInt(128)
	msgEncrypt, _ := rand.Int(rand.Reader, size)
	fmt.Print("The generated message: ")
	fmt.Println(msgEncrypt)

	msg, hash := rsacustom.Sign(private, msgEncrypt)
	fmt.Print("Signed message: ")
	fmt.Println(msg)

	//Verify correct message
	rsacustom.Verify(public, msg, hash)

	//Verify incorrect message
	tamperedMEssage := big.NewInt(88558698261037034)
	rsacustom.Verify(public, tamperedMEssage, hash)
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
	fmt.Println("AESKey used to encrypt/decrypt: 	" + AESKey)

	// Encrypt the RSAPrivateKey to a cipher text and place it in "aes.txt"
	RSAPrivateKey := fmt.Sprintf("%s", private.D)
	encrypted := aestofile.EncryptToFile(RSAPrivateKey, AESKey)
	fmt.Println("Encrypted (Cipher text):		" + encrypted)

	// Decrypt the RSAPrivateKey from "aes.txt" and print it on the console
	decrypted := aestofile.DecryptToFile(AESKey, "aes.txt")
	fmt.Println("Decrypted cipher text (RSAPrivateKey):	" + decrypted)

	// Convert RSAPrivateKey from string to big.int
	temp := new(big.Int)
	temp.SetString(decrypted, 10)

	// Create new key object with the key from "aes.txt"
	privateKeyFromTxtFile := &rsacustom.PrivateKey{N: private.N, D: temp}

	// Try to decrypt the cipher text created by Encrypt() with the key found in "aes.txt"
	msgDecryptOld := rsacustom.Decrypt(privateKeyFromTxtFile, c)
	fmt.Print("Decrypted message:			")
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
