package crypto

import (
	"crypto/md5"
)

type Encrypter interface {
	Encrypt(dst, src []byte)
}

type Decrypter interface {
	Decrypt(dst, src []byte)
}

type EncrypterInPlace interface {
	EncryptInPlace(data []byte)
}

type DecrypterInPlace interface {
	DecryptInPlace(data []byte)
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
