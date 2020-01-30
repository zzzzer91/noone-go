package conf

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

var S *SSConf

func LoadJson(path string) {
	S = &SSConf{
		Server:     "0.0.0.0",
		ServerPort: 9530,
		Password:   "123456",
		Timeout:    300,
		Method:     "aes-128-ctr",
		FastOpen:   true,
	}
}
