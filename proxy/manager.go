package proxy

import (
	"fmt"
	"io"
	"net"
	"newt/logger"
	"strings"
	"sync"
	"time"

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

	logger.Info("Adding target: %s://%s:%d -> %s", protocol, listen, port, target)

	newTarget := ProxyTarget{
		Protocol: protocol,
		Listen:   listen,
		Port:     port,
		Target:   target,
		cancel:   make(chan struct{}),
		done:     make(chan struct{}),
	}

	pm.targets = append(pm.targets, newTarget)
}

func (pm *ProxyManager) RemoveTarget(protocol, listen string, port int) error {
	pm.Lock()
	defer pm.Unlock()

	protocol = strings.ToLower(protocol)
	if protocol != "tcp" && protocol != "udp" {
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	for i, target := range pm.targets {
		if target.Listen == listen &&
			target.Port == port &&
			strings.ToLower(target.Protocol) == protocol {

			// Signal the serving goroutine to stop
			select {
			case <-target.cancel:
				// Channel is already closed, no need to close it again
			default:
				close(target.cancel)
			}

			// Close the appropriate listener/connection based on protocol
			target.Lock()
			switch protocol {
			case "tcp":
				if target.listener != nil {
					select {
					case <-target.cancel:
						// Listener was already closed by Stop()
					default:
						target.listener.Close()
					}
				}
			case "udp":
				if target.udpConn != nil {
					select {
					case <-target.cancel:
						// Connection was already closed by Stop()
					default:
						target.udpConn.Close()
					}
				}
			}
			target.Unlock()

			// Wait for the target to fully stop
			<-target.done

			// Remove the target from the slice
			pm.targets = append(pm.targets[:i], pm.targets[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("target not found for %s %s:%d", protocol, listen, port)
}

func (pm *ProxyManager) Start() error {
	pm.RLock()
	defer pm.RUnlock()

	for i := range pm.targets {
		target := &pm.targets[i]

		target.Lock()
		// If target is already running, skip it
		if target.listener != nil || target.udpConn != nil {
			target.Unlock()
			continue
		}

		// Mark the target as starting by creating a nil listener/connection
		// This prevents other goroutines from trying to start it
		if strings.ToLower(target.Protocol) == "tcp" {
			target.listener = nil
		} else {
			target.udpConn = nil
		}
		target.Unlock()

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

func (pm *ProxyManager) Stop() error {
	pm.Lock()
	defer pm.Unlock()

	var wg sync.WaitGroup
	for i := range pm.targets {
		target := &pm.targets[i]
		wg.Add(1)
		go func(t *ProxyTarget) {
			defer wg.Done()
			close(t.cancel)
			t.Lock()
			if t.listener != nil {
				t.listener.Close()
			}
			if t.udpConn != nil {
				t.udpConn.Close()
			}
			t.Unlock()
			// Wait for the target to fully stop
			<-t.done
		}(target)
	}
	wg.Wait()
	return nil
}

func (pm *ProxyManager) serveTCP(target *ProxyTarget) {
	defer close(target.done) // Signal that this target is fully stopped

	listener, err := pm.tnet.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP(target.Listen),
		Port: target.Port,
	})
	if err != nil {
		logger.Info("Failed to start TCP listener for %s:%d: %v", target.Listen, target.Port, err)
		return
	}

	target.Lock()
	target.listener = listener
	target.Unlock()

	defer listener.Close()
	logger.Info("TCP proxy listening on %s", listener.Addr())

	var activeConns sync.WaitGroup
	acceptDone := make(chan struct{})

	// Goroutine to handle shutdown signal
	go func() {
		<-target.cancel
		close(acceptDone)
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
				logger.Info("Failed to accept TCP connection: %v", err)
				// Don't return here, try to accept new connections
				time.Sleep(time.Second)
				continue
			}
		}

		activeConns.Add(1)
		go func() {
			defer activeConns.Done()
			pm.handleTCPConnection(conn, target.Target, acceptDone)
		}()
	}
}

func (pm *ProxyManager) handleTCPConnection(clientConn net.Conn, target string, done chan struct{}) {
	defer clientConn.Close()

	serverConn, err := net.Dial("tcp", target)
	if err != nil {
		logger.Info("Failed to connect to target %s: %v", target, err)
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
	defer close(target.done) // Signal that this target is fully stopped

	addr := &net.UDPAddr{
		IP:   net.ParseIP(target.Listen),
		Port: target.Port,
	}

	conn, err := pm.tnet.ListenUDP(addr)
	if err != nil {
		logger.Info("Failed to start UDP listener for %s:%d: %v", target.Listen, target.Port, err)
		return
	}

	target.Lock()
	target.udpConn = conn
	target.Unlock()

	defer conn.Close()
	logger.Info("UDP proxy listening on %s", conn.LocalAddr())

	buffer := make([]byte, 65535)
	var activeConns sync.WaitGroup

	for {
		select {
		case <-target.cancel:
			activeConns.Wait() // Wait for all active UDP handlers to complete
			return
		default:
			n, remoteAddr, err := conn.ReadFrom(buffer)
			if err != nil {
				select {
				case <-target.cancel:
					activeConns.Wait()
					return
				default:
					logger.Info("Failed to read UDP packet: %v", err)
					continue
				}
			}

			targetAddr, err := net.ResolveUDPAddr("udp", target.Target)
			if err != nil {
				logger.Info("Failed to resolve target address %s: %v", target.Target, err)
				continue
			}

			activeConns.Add(1)
			go func(data []byte, remote net.Addr) {
				defer activeConns.Done()
				targetConn, err := net.DialUDP("udp", nil, targetAddr)
				if err != nil {
					logger.Info("Failed to connect to target %s: %v", target.Target, err)
					return
				}
				defer targetConn.Close()

				select {
				case <-target.cancel:
					return
				default:
					_, err = targetConn.Write(data)
					if err != nil {
						logger.Info("Failed to write to target: %v", err)
						return
					}

					response := make([]byte, 65535)
					n, err := targetConn.Read(response)
					if err != nil {
						logger.Info("Failed to read response from target: %v", err)
						return
					}

					_, err = conn.WriteTo(response[:n], remote)
					if err != nil {
						logger.Info("Failed to write response to client: %v", err)
					}
				}
			}(buffer[:n], remoteAddr)
		}
	}
}
