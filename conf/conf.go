package conf

import (
	"encoding/json"
	"io/ioutil"
)

type SSConf struct {
	Server       string
	ServerPort   uint16
	LocalAddress string
	LocalPort    uint16
	Password     string
	Timeout      int
	Method       string
	PortPassword map[string]string
	FastOpen     bool
}

var SS *SSConf

func LoadJson(path string) error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	var conf SSConf
	err = json.Unmarshal(b, &conf)
	if err != nil {
		return err
	}
	SS = &conf
	return nil
}
