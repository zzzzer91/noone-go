package trojan

const (
	commandTCP byte = 1
	commandUDP byte = 3
)

const (
	fallbackHttpBody = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: text/plain;charset=UTF-8\r\n\r\nHello world"
)
