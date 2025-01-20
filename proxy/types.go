package proxy

import (
	"log"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type ProxyTarget struct {
	Protocol    string
	Listen      string
	Port        int
	Target      string
	cancel      chan struct{}  // Channel to signal shutdown
	done        chan struct{}  // Channel to signal completion
	listener    net.Listener   // For TCP
	udpConn     net.PacketConn // For UDP
	sync.Mutex                 // Protect access to connection
	activeConns sync.Map
}

type ProxyManager struct {
	targets      []*ProxyTarget
	tnet         *netstack.Net
	log          *log.Logger
	sync.RWMutex // Protect access to targets slice
}
