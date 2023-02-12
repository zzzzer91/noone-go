package user

import (
	"noone/app/conf"
	"noone/app/crypto"
)

type User struct {
	Server   string
	Port     int
	Method   string
	Password string
	Key      []byte
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
		}
	}
	return users
}
