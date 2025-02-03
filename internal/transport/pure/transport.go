package pure

type Transporter interface {
	Read() error
	Write() error
	Close()
	Network() string
}
