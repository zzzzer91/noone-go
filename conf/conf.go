package conf

import (
	"encoding/json"
	"io/ioutil"
)

type SSConf struct {
	Servers []struct {
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
		Password   string `json:"password"`
		Method     string `json:"method"`
	} `json:"servers"`
}

func LoadJson(path string) (*SSConf, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conf SSConf
	err = json.Unmarshal(b, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
