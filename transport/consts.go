package transport

const (
	StageInit      = iota // 解析 header 阶段，获取 iv, remote 的 ip 和 port
	StageHandShake        // TCP 和 remote 握手阶段
	StageStream           // TCP 传输阶段
	StageDestroyed        // 该连接已销毁
)

// atyp
const (
	AtypIpv4   = 0x01
	AtypDomain = 0x03
	AtypIpv6   = 0x04
)
