package manager

import (
	"noone/app/config"
	"noone/app/crypto"
)

type Proxy struct {
	Server   string
	Port     int
	Cipher   string
	Password string
	Key      []byte
}

func initProxies(conf *config.Conf) []*Proxy {
	proxies := make([]*Proxy, len(conf.Proxies))
	for i, s := range conf.Proxies {
		proxies[i] = &Proxy{
			Server:   s.Server,
			Port:     s.Port,
			Cipher:   s.Cipher,
			Password: s.Password,
			Key:      crypto.Kdf(s.Password, 16),
		}
	}
	return proxies
}
