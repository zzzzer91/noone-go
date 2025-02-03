package simplesocks

type (
	CmdType byte
)

func (c CmdType) IsValid() bool {
	switch c {
	case CmdTypeTCP, CmdTypeUDP:
		return true
	}
	return false
}

func (c CmdType) NetWork() string {
	switch c {
	case CmdTypeTCP:
		return "tcp"
	case CmdTypeUDP:
		return "udp"
	}
	return ""
}

const (
	CmdTypeUnspecified CmdType = 0
	CmdTypeTCP         CmdType = 1
	CmdTypeUDP         CmdType = 3
)
