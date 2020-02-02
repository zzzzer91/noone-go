package tcp

const (
	// client 发送过来的数据一般比较短
	clientBufCapacity = 2 * 1024
	remoteBufCapacity = 8 * 1024
)
