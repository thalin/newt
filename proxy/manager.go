package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func NewProxyManager(tnet *netstack.Net) *ProxyManager {
	return &ProxyManager{
		tnet: tnet,
	}
}

func (pm *ProxyManager) AddTarget(protocol, listen string, port int, target string) {
	pm.Lock()
	defer pm.Unlock()

	newTarget := ProxyTarget{
		Protocol: protocol,
		Listen:   listen,
		Port:     port,
		Target:   target,
		cancel:   make(chan struct{}),
	}

	pm.targets = append(pm.targets, newTarget)
}

func (pm *ProxyManager) RemoveTarget(listen string, port int) error {
	pm.Lock()
	defer pm.Unlock()

	for i, target := range pm.targets {
		if target.Listen == listen && target.Port == port {
			// Signal the serving goroutine to stop
			close(target.cancel)

			// Close the listener/connection
			target.Lock()
			if target.listener != nil {
				target.listener.Close()
			}
			if target.udpConn != nil {
				target.udpConn.Close()
			}
			target.Unlock()

			// Remove the target from the slice
			pm.targets = append(pm.targets[:i], pm.targets[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("target not found for %s:%d", listen, port)
}

func (pm *ProxyManager) Start() error {
	pm.RLock()
	defer pm.RUnlock()

	for i := range pm.targets {
		target := &pm.targets[i] // Use pointer to modify the target in the slice
		switch strings.ToLower(target.Protocol) {
		case "tcp":
			go pm.serveTCP(target)
		case "udp":
			go pm.serveUDP(target)
		default:
			return fmt.Errorf("unsupported protocol: %s", target.Protocol)
		}
	}
	return nil
}

func (pm *ProxyManager) serveTCP(target *ProxyTarget) {
	listener, err := pm.tnet.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP(target.Listen),
		Port: target.Port,
	})
	log.Printf("Listening on %s:%d", target.Listen, target.Port)
	if err != nil {
		log.Printf("Failed to start TCP listener for %s:%d: %v", target.Listen, target.Port, err)
		return
	}

	target.Lock()
	target.listener = listener
	target.Unlock()

	defer listener.Close()
	log.Printf("TCP proxy listening on %s", listener.Addr())

	// Channel to signal active connections to close
	done := make(chan struct{})
	var activeConns sync.WaitGroup

	// Goroutine to handle shutdown signal
	go func() {
		<-target.cancel
		close(done)
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-target.cancel:
				// Wait for active connections to finish
				activeConns.Wait()
				return
			default:
				log.Printf("Failed to accept TCP connection: %v", err)
				continue
			}
		}

		activeConns.Add(1)
		go func() {
			defer activeConns.Done()
			pm.handleTCPConnection(conn, target.Target, done)
		}()
	}
}

func (pm *ProxyManager) handleTCPConnection(clientConn net.Conn, target string, done chan struct{}) {
	defer clientConn.Close()

	serverConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", target, err)
		return
	}
	defer serverConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Server
	go func() {
		defer wg.Done()
		select {
		case <-done:
			return
		default:
			io.Copy(serverConn, clientConn)
		}
	}()

	// Server -> Client
	go func() {
		defer wg.Done()
		select {
		case <-done:
			return
		default:
			io.Copy(clientConn, serverConn)
		}
	}()

	wg.Wait()
}

func (pm *ProxyManager) serveUDP(target *ProxyTarget) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(target.Listen),
		Port: target.Port,
	}

	conn, err := pm.tnet.ListenUDP(addr)
	if err != nil {
		log.Printf("Failed to start UDP listener for %s:%d: %v", target.Listen, target.Port, err)
		return
	}

	target.Lock()
	target.udpConn = conn
	target.Unlock()

	defer conn.Close()
	log.Printf("UDP proxy listening on %s", conn.LocalAddr())

	buffer := make([]byte, 65535)

	for {
		select {
		case <-target.cancel:
			return
		default:
			n, remoteAddr, err := conn.ReadFrom(buffer)
			if err != nil {
				select {
				case <-target.cancel:
					return
				default:
					log.Printf("Failed to read UDP packet: %v", err)
					continue
				}
			}

			targetAddr, err := net.ResolveUDPAddr("udp", target.Target)
			if err != nil {
				log.Printf("Failed to resolve target address %s: %v", target.Target, err)
				continue
			}

			go func(data []byte, remote net.Addr) {
				targetConn, err := net.DialUDP("udp", nil, targetAddr)
				if err != nil {
					log.Printf("Failed to connect to target %s: %v", target.Target, err)
					return
				}
				defer targetConn.Close()

				select {
				case <-target.cancel:
					return
				default:
					_, err = targetConn.Write(data)
					if err != nil {
						log.Printf("Failed to write to target: %v", err)
						return
					}

					response := make([]byte, 65535)
					n, err := targetConn.Read(response)
					if err != nil {
						log.Printf("Failed to read response from target: %v", err)
						return
					}

					_, err = conn.WriteTo(response[:n], remote)
					if err != nil {
						log.Printf("Failed to write response to client: %v", err)
					}
				}
			}(buffer[:n], remoteAddr)
		}
	}
}
