package pure

const (
	// client 发送过来的数据一般比较短
	TcpClientBufCapacity = 16 * 1024
	// 看视频时，大容量 Buffer 有利于减少系统调用
	TcpRemoteBufCapacity = 32 * 1024
)

const (
	UdpClientBufCapacity = 4 * 1024
	UdpRemoteBufCapacity = 4 * 1024
)
