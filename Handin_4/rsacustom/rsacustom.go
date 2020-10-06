package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"rsacustom"
)

func main() {
	public, private, _ := rsacustom.KeyGen(128)
	size := big.NewInt(128)
	msgEncrypt, _ := rand.Int(rand.Reader, size)

	fmt.Print("Plaintext: ")
	fmt.Println(msgEncrypt)

	c := rsacustom.Sign(private, msgEncrypt)
	fmt.Print("\nHashed and signed text: ")
	fmt.Println(c)

	dc := rsacustom.Verify(public, c)
	fmt.Print("After verify: ")
	fmt.Println(dc)
}

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

// Sign signs messages by first hashng them and then signing
func Sign(privKey *PrivateKey, m *big.Int) *big.Int {
	hash := sha256.New()
	hash.Write(m.Bytes())
	hashed := hash.Sum(nil)
	rsa.PrivateKey(privKey.D)
	c := rsa.SignPKCS1v15(rand.Reader, privKey.D)
	return c
}

// Verify does something
func Verify(pub *PublicKey, cipher *big.Int) *big.Int {
	hash := sha256.New()
	hash.Write(cipher.Bytes())
	hashed := h.Sum256(nil)
	c := rsa.VerifyPKCS1v15()

	return hashedMessage
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
