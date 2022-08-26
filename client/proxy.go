package chclient

import (
	"fmt"
	"io"
	"net"

	"github.com/jpillora/chisel/share"
)

type tcpProxy struct {
	*chshare.Logger
	client *Client
	id     int
	count  int
	remote *chshare.Remote
	listener net.Listener
}

func newTCPProxy(c *Client, index int, remote *chshare.Remote) *tcpProxy {
	id := index + 1
	return &tcpProxy{
		Logger: c.Logger.Fork("tunnel#%d %s", id, remote),
		client: c,
		id:     id,
		remote: remote,
	}
}

func (p *tcpProxy) start() error {
	l, err := net.Listen("tcp4", p.remote.LocalHost+":"+p.remote.LocalPort)
	if err != nil {
		return fmt.Errorf("%s: %s", p.Logger.Prefix(), err)
	}
	p.listener = l
	go p.listen()
	return nil
}

func (p *tcpProxy) listen() {
	p.Infof("Listening")
	for {
		src, err := p.listener.Accept()
		if err != nil {
			p.Infof("Accept error: %s", err)
			return
		}
		go p.accept(src)
	}
	p.Infof("Done listening")
}

func (p *tcpProxy) accept(src io.ReadWriteCloser) {
	p.count++
	cid := p.count
	l := p.Fork("conn#%d", cid)
	l.Infof("Open")
	if p.client.sshConn == nil {
		l.Infof("No server connection")
		src.Close()
		return
	}
	dst, err := chshare.OpenStream(p.client.sshConn, p.remote.Remote())
	if err != nil {
		l.Infof("Stream error: %s", err)
		src.Close()
		return
	}
	//then pipe
	s, r := chshare.Pipe(src, dst)
	l.Infof("Close (sent %d received %d)", s, r)
}

func (p *tcpProxy) stop() error {
	if p.listener != nil {
		p.Infof("Closing")
		err := p.listener.Close()
		p.listener = nil
		return err
	}
	return nil
}
