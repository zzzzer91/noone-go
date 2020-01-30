package tcp

import (
	"net"
	"noone/transport"
)

func handleConn(conn net.Conn) {
	c := transport.New(conn)
	if c.Stage == transport.StageInit {
		c.HandleStageInit()
	}
	if c.Stage == transport.StageHeader {
		c.HandleStageHeader()
	}
	if c.Stage == transport.StageDns {
		c.HandleStageDns()
	}
	if c.Stage == transport.StageHandShake {
		c.HandleStageHandShake()
	}
	if c.Stage == transport.StageStream {
		c.HandleStream()
	}
}
