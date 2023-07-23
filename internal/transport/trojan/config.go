package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/zzzzer91/noone/internal/config"
)

type trojanConf struct {
	name        string
	addr        string
	hexPassword []byte
	cn          string
	alpn        []string
}

func convertTrojanConf(p *config.Proxy) *trojanConf {
	return &trojanConf{
		name:        p.Name,
		addr:        p.Server + ":" + strconv.Itoa(p.Port),
		hexPassword: hexSha224([]byte(p.Password)),
		cn:          p.CommonName,
		alpn:        p.Alpn,
	}
}

func hexSha224(data []byte) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write(data)
	hex.Encode(buf, hash.Sum(nil))
	return buf
}
