package proxy

import (
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type ProxyTarget struct {
	Protocol   string
	Listen     string
	Port       int
	Target     string
	cancel     chan struct{}  // Channel to signal shutdown
	listener   net.Listener   // For TCP
	udpConn    net.PacketConn // For UDP
	sync.Mutex                // Protect access to connections
}

type ProxyManager struct {
	targets      []ProxyTarget
	tnet         *netstack.Net
	sync.RWMutex // Protect access to targets slice
}
