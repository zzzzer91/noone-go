package ss

import (
	"noone/app/config"
	"noone/app/crypto"
	"strconv"
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
