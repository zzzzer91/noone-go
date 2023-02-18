package ss

import (
	"noone/app/config"
	"noone/app/crypto"
)

type ssConf struct {
	server string
	port   int
	cipher string
	Key    []byte
}

func convertSsConf(p *config.Proxy) *ssConf {
	return &ssConf{
		server: p.Server,
		port:   p.Port,
		cipher: p.Cipher,
		Key:    crypto.Kdf(p.Password, 16),
	}
}
