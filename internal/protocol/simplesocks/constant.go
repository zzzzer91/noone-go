package simplesocks

var (
	MinClientHeaderLength = 66
	MaxUDPHeaderLength    = 255 + 1 + 1 + 2 + 2 + 2
	PasswordLength        = 56
	Crlf                  = "\r\n"
)

const (
	atypIpv4   = 0x01
	atypDomain = 0x03
	atypIpv6   = 0x04
)
