package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

type CtrEncryptCtx struct {
	x cipher.Stream
}

func NewCtrEncrypter(key, iv []byte) *CtrEncryptCtx {
	encryptBlock, _ := aes.NewCipher(key)
	return &CtrEncryptCtx{
		x: cipher.NewCTR(encryptBlock, iv),
	}
}

func (c *CtrEncryptCtx) Encrypt(dst, src []byte) {
	c.x.XORKeyStream(dst, src)
}

func (c *CtrEncryptCtx) EncryptInPlace(data []byte) {
	c.Encrypt(data, data)
}

type CtrDecryptCtx struct {
	x cipher.Stream
}

func NewCtrDecrypter(key, iv []byte) *CtrDecryptCtx {
	decryptBlock, _ := aes.NewCipher(key)
	return &CtrDecryptCtx{
		x: cipher.NewCTR(decryptBlock, iv),
	}
}

func (c *CtrDecryptCtx) Decrypt(dst, src []byte) {
	c.x.XORKeyStream(dst, src)
}

func (c *CtrDecryptCtx) DecryptInPlace(data []byte) {
	c.Decrypt(data, data)
}
