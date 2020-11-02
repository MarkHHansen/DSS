package rsacustom

import (
	"crypto/rand"
	"fmt"
	"math/big"
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
