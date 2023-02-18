package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Conf struct {
	Proxies []*Proxy `yaml:"proxies"`
}

type Proxy struct {
	Name       string   `yaml:"name"`
	Type       string   `yaml:"type"`
	Server     string   `yaml:"server"`
	Port       int      `yaml:"port"`
	Password   string   `yaml:"password"`
	Cipher     string   `yaml:"cipher"`
	CommonName string   `yaml:"cn"`
	Alpn       []string `yaml:"alpn"`
}

func LoadConf(path string) (*Conf, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conf Conf
	err = yaml.Unmarshal(b, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
