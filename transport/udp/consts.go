package udp

const (
	// TODO 预分配多少合适？，太大会分配在堆上
	clientBufCapacity = 2 * 1024
	remoteBufCapacity = 2 * 1024
)
