package tcp

const (
	// client 发送过来的数据一般比较短
	clientBufCapacity = 4 * 1024
	// 看视频时，大容量 Buffer 有利于减少系统调用
	remoteBufCapacity = 16 * 1024
)
