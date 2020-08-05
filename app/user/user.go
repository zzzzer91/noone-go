package user

import (
	"noone/app/conf"
	"noone/app/crypto"
	"noone/app/dnscache"
	"sync"
)

type User struct {
	Server   string
	Port     int
	Method   string
	Password string
	Key      []byte

	DnsCache *dnscache.Cache // Every user has own DNS cache

	lock sync.RWMutex
}

func InitUsers(ssConf *conf.SSConf) []*User {
	users := make([]*User, len(ssConf.Users))
	for i, s := range ssConf.Users {
		users[i] = &User{
			Server:   s.Server,
			Port:     s.ServerPort,
			Method:   s.Method,
			Password: s.Password,
			Key:      crypto.Kdf(s.Password, 16),
			DnsCache: dnscache.NewCache(),
		}
	}
	return users
}
