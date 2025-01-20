package proxy

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func NewProxyManager(tnet *netstack.Net) *ProxyManager {
	return &ProxyManager{
		tnet: tnet,
	}
}

func (pm *ProxyManager) AddTarget(protocol, listen string, port int, target string) error {
	pm.Lock()
	defer pm.Unlock()

	logger.Info("Adding target: %s://%s:%d -> %s", protocol, listen, port, target)
	newTarget := &ProxyTarget{
		Protocol: protocol,
		Listen:   listen,
		Port:     port,
		Target:   target,
		cancel:   make(chan struct{}),
		done:     make(chan struct{}),
	}

	pm.targets = append(pm.targets, newTarget)
	return nil
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
				// Channel is already closed
			default:
				close(target.cancel)
			}

			// Close the listener/connection
			target.Lock()
			switch protocol {
			case "tcp":
				if target.listener != nil {
					target.listener.Close()
				}
			case "udp":
				if target.udpConn != nil {
					target.udpConn.Close()
				}
			}
			target.Unlock()

			// Wait for the target to fully stop
			<-target.done

			pm.targets = append(pm.targets[:i], pm.targets[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("target not found for %s %s:%d", protocol, listen, port)
}

func (pm *ProxyManager) Start() error {
	pm.RLock()
	defer pm.RUnlock()

	for _, target := range pm.targets {
		target.Lock()
		// If target is already running, skip it
		if target.listener != nil || target.udpConn != nil {
			target.Unlock()
			continue
		}

		// Mark the target as starting by creating a nil listener/connection
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
	for _, target := range pm.targets {
		wg.Add(1)
		// Create a new variable in the loop to avoid closure issues
		t := target // Take a local copy
		go func() {
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
		}()
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

	// Create error channels for both copy operations
	errc1 := make(chan error, 1)
	errc2 := make(chan error, 1)

	// Copy from client to server
	go func() {
		_, err := io.Copy(serverConn, clientConn)
		errc1 <- err
	}()

	// Copy from server to client
	go func() {
		_, err := io.Copy(clientConn, serverConn)
		errc2 <- err
	}()

	// Wait for either copy to finish or done signal
	select {
	case <-done:
		// Gracefully close connections without type assertions
		if closer, ok := clientConn.(interface{ CloseRead() error }); ok {
			closer.CloseRead()
		}
		if closer, ok := serverConn.(*gonet.TCPConn); ok {
			closer.CloseRead()
		}
	case err := <-errc1:
		if err != nil {
			logger.Info("Error copying client->server: %v", err)
		}
	case err := <-errc2:
		if err != nil {
			logger.Info("Error copying server->client: %v", err)
		}
	}
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
