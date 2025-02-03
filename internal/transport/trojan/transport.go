package trojan

type Transporter interface {
	Read() error
	Write() error
	Close()
	Network() string
}
