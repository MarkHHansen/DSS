package aestofile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// EncryptToFile encrypts a message and prints it to a file
func EncryptToFile(stringToEncrypt string, keyString string, fileName string) (encryptedString string) {
	//Create aes.txt file
	file, err := os.Create(fileName)
	if err != nil {
		// Open aes.txt file
		file, err = os.Open(fileName)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	//Since the key is in string, we need to convert decode it to bytes
	key := []byte(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	ciphertextByte := aesGCM.Seal(nonce, nonce, plaintext, nil)
	cipherString := fmt.Sprintf("%x", ciphertextByte)

	//Write ciphertext to file
	_, err = file.WriteString(cipherString)
	if err != nil {
		fmt.Println(err)
		file.Close()
		return
	}

	return cipherString

}

// DecryptToFile decrypts a message in a file and prints it in the console
func DecryptToFile(keyString string, fileName string) (decryptedString string) {
	// Read from aes.txt file
	c, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Println(err)
		return "File does not exists"
	}

	cipherString := string(c)

	key := []byte(keyString)
	enc, _ := hex.DecodeString(cipherString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)

}
