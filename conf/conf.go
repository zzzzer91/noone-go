package conf

import (
	"encoding/json"
	"io/ioutil"
)

type SSConf struct {
	Server       string            `json:"server"`
	ServerPort   int               `json:"server_port"`
	Password     string            `json:"password"`
	Timeout      int               `json:"timeout"`
	Method       string            `json:"method"`
	PortPassword map[string]string `json:"port_password"`
}

func LoadJson(path string) (SSConf, error) {
	var conf SSConf
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return conf, err
	}
	err = json.Unmarshal(b, &conf)
	if err != nil {
		return conf, err
	}
	return conf, nil
}
