package crypto

import (
	"crypto/md5"
)

type Cipher interface {
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
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
