package trojan

const (
	commandTCP byte = 1
	commandUDP byte = 3
)

// atyp
const (
	atypIpv4   = 0x01
	atypDomain = 0x03
	atypIpv6   = 0x04
)

const (
	// client 发送过来的数据一般比较短
	tcpClientBufCapacity = 16 * 1024
	// 看视频时，大容量 Buffer 有利于减少系统调用
	tcpRemoteBufCapacity = 32 * 1024
)
