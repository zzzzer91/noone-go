package conf

import (
	"encoding/json"
	"io/ioutil"
)

type SSConf struct {
	Server       string            `json:"server"`
	ServerPort   uint16            `json:"server_port"`
	Password     string            `json:"password"`
	Timeout      int               `json:"timeout"`
	Method       string            `json:"method"`
	PortPassword map[string]string `json:"port_password"`
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
