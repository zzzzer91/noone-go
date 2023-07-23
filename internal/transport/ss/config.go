package ss

import (
	"strconv"

	"github.com/zzzzer91/noone/internal/config"
	"github.com/zzzzer91/noone/internal/crypto"
)

type ssConf struct {
	name   string
	addr   string
	cipher string
	Key    []byte
}

func convertSsConf(p *config.Proxy) *ssConf {
	return &ssConf{
		name:   p.Name,
		addr:   p.Server + ":" + strconv.Itoa(p.Port),
		cipher: p.Cipher,
		Key:    crypto.Kdf(p.Password, 16),
	}
}
