package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
)

type Cipher interface {
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

type ctx struct {
	encryptCtx cipher.Stream
	decryptCtx cipher.Stream
}

func New(key, iv []byte) *ctx {
	encryptBlock, _ := aes.NewCipher(key)
	decryptBlock, _ := aes.NewCipher(key)
	return &ctx{
		encryptCtx: cipher.NewCTR(encryptBlock, iv),
		decryptCtx: cipher.NewCTR(decryptBlock, iv),
	}
}

func (c *ctx) Encrypt(dst, src []byte) {
	c.encryptCtx.XORKeyStream(dst, src)
}

func (c *ctx) Decrypt(dst, src []byte) {
	c.decryptCtx.XORKeyStream(dst, src)
}

// key-derivation function from original Shadowsocks
func Kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
