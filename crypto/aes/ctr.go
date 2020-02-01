package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

type Ctr struct {
	encryptCtx cipher.Stream
	decryptCtx cipher.Stream
}

func NewCtr(key, encryptIV, decryptIV []byte) *Ctr {
	encryptBlock, _ := aes.NewCipher(key)
	decryptBlock, _ := aes.NewCipher(key)
	return &Ctr{
		encryptCtx: cipher.NewCTR(encryptBlock, encryptIV),
		decryptCtx: cipher.NewCTR(decryptBlock, decryptIV),
	}
}

func (c *Ctr) Encrypt(dst, src []byte) {
	c.encryptCtx.XORKeyStream(dst, src)
}

func (c *Ctr) Decrypt(dst, src []byte) {
	c.decryptCtx.XORKeyStream(dst, src)
}
