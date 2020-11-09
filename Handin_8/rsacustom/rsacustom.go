package rsacustom

import (
	"aestofile"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

// PublicKey consists of N and E of type big.int
type PublicKey struct {
	N *big.Int
	E *big.Int
}

// PrivateKey consists of N and D of type big.int
type PrivateKey struct {
	N *big.Int
	D *big.Int
}

//Generate writes a encrypted secret key to a file, and returns a public key
func Generate(filename string, password string) string {
	pubKey, privKey, err := KeyGen(256)
	if err != nil {
		return "Error in keygen"
	}
	if len(password) != 16 || len(password) != 16 {
		return "Password incorrect size!"
	}
	privKeyString := privKey.N.String() + "," + privKey.D.String()

	//Uses aestofile function to encrypt the private key with the password
	aestofile.EncryptToFile(privKeyString, password, filename)

	return "PubKey," + pubKey.N.String() + "," + pubKey.E.String()
}

//Sign will sign a msg, with a secret key if the password is correct.
func Sign(filename string, password string, msg []byte) *big.Int {
	//Uses aestofile function to decrypt the private key with the password. And sign with this key
	decryted := aestofile.DecryptToFile(password, filename)
	if decryted == "File does not exists" {
		returnV := new(big.Int).SetUint64(0)
		return returnV
	}
	decryptedArray := strings.Split(decryted, ",")
	signKey := new(PrivateKey)
	signKey.N, _ = new(big.Int).SetString(decryptedArray[0], 10)
	signKey.D, _ = new(big.Int).SetString(decryptedArray[1], 10)

	signMsg := new(big.Int).SetBytes(msg)
	signedMsg, _ := SignOld(signKey, signMsg)
	return signedMsg
}

// SignOld signs messages by first hashng them and then signing
func SignOld(privKey *PrivateKey, m *big.Int) (*big.Int, *big.Int) {
	hashedMessage := Hash(m)
	signed := new(big.Int).Exp(hashedMessage, privKey.D, privKey.N)
	return signed, hashedMessage
}

// Verify verifies the message is from a trustworthy sender
func Verify(pub *PublicKey, signature *big.Int, hash *big.Int) bool {
	//hashedMessage := new(big.Int)
	hashFromSignature := new(big.Int).Exp(signature, pub.E, pub.N)

	if hashFromSignature.Cmp(hash) == 0 {
		fmt.Println("The message is verified")
		return true
	}

	fmt.Println("The message is not verified")
	return false

}

// Hash generates a sha256 hash
func Hash(message *big.Int) *big.Int {
	hash := sha256.Sum256(message.Bytes())
	returnHash := new(big.Int).SetBytes(hash[:])
	return returnHash
}

// KeyGen generates a publickey and a privatekey
func KeyGen(k int) (*PublicKey, *PrivateKey, error) {
	counter := 0

	for {
		counter++
		if counter == 10 {
			panic("Retrying too many times")
		}

		p, err := rand.Prime(rand.Reader, k/2)
		if err != nil {
			return nil, nil, err
		}
		q, err := rand.Prime(rand.Reader, k/2)
		if err != nil {
			return nil, nil, err
		}

		// n =  p*q
		n := new(big.Int).Set(p)
		n.Mul(n, q)

		if n.BitLen() != k {
			fmt.Print("n value not equal k lenght: ")
			fmt.Println(n)
			continue
		}

		// theta(n) = (p-1)(q-1)
		p.Sub(p, big.NewInt(1))
		q.Sub(q, big.NewInt(1))
		totient := new(big.Int).Set(p)
		totient.Mul(totient, q)

		// e is set to the specified value from the exercise
		e := big.NewInt(3)

		// Calculate the modular multiplicative inverse of e
		d := new(big.Int).ModInverse(e, totient)

		if d == nil {
			continue
		}

		public := &PublicKey{N: n, E: e}
		private := &PrivateKey{N: n, D: d}

		return public, private, nil
	}
}

//Encrypt encrypts the message using the publickey
func Encrypt(pub *PublicKey, m *big.Int) *big.Int {
	c := new(big.Int)
	c.Exp(m, pub.E, pub.N)
	return c
}

// Decrypt decrypts the cipher text using the privatekey
func Decrypt(priv *PrivateKey, c *big.Int) *big.Int {
	m := new(big.Int)
	m.Exp(c, priv.D, priv.N)
	return m

}
