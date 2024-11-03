package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type ProxyTarget struct {
	Protocol string
	Listen   string
	Targets  []string
}

type ProxyManager struct {
	targets []ProxyTarget
	tnet    *netstack.Net
}

func NewProxyManager(tnet *netstack.Net) *ProxyManager {
	return &ProxyManager{
		tnet: tnet,
	}
}

func (pm *ProxyManager) AddTarget(protocol, listen string, targets []string) {
	pm.targets = append(pm.targets, ProxyTarget{
		Protocol: protocol,
		Listen:   listen,
		Targets:  targets,
	})
}

func (pm *ProxyManager) Start() error {
	for _, target := range pm.targets {
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

func (pm *ProxyManager) serveTCP(target ProxyTarget) {
	listener, err := pm.tnet.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP(target.Listen),
		Port: 0,
	})
	if err != nil {
		log.Printf("Failed to start TCP listener for %s: %v", target.Listen, err)
		return
	}
	defer listener.Close()

	log.Printf("TCP proxy listening on %s", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept TCP connection: %v", err)
			continue
		}

		go pm.handleTCPConnection(conn, target.Targets)
	}
}

func (pm *ProxyManager) handleTCPConnection(clientConn net.Conn, targets []string) {
	defer clientConn.Close()

	// Round-robin through targets
	targetIndex := 0
	target := targets[targetIndex]
	targetIndex = (targetIndex + 1) % len(targets)

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
		io.Copy(serverConn, clientConn)
	}()

	// Server -> Client
	go func() {
		defer wg.Done()
		io.Copy(clientConn, serverConn)
	}()

	wg.Wait()
}

func (pm *ProxyManager) serveUDP(target ProxyTarget) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(target.Listen),
		Port: 0,
	}

	conn, err := pm.tnet.ListenUDP(addr)
	if err != nil {
		log.Printf("Failed to start UDP listener for %s: %v", target.Listen, err)
		return
	}
	defer conn.Close()

	log.Printf("UDP proxy listening on %s", conn.LocalAddr())

	buffer := make([]byte, 65535)
	targetIndex := 0

	for {
		// Read from the UDP connection
		n, remoteAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Printf("Failed to read UDP packet: %v", err)
			continue
		}

		t := target.Targets[targetIndex]
		targetIndex = (targetIndex + 1) % len(target.Targets)

		targetAddr, err := net.ResolveUDPAddr("udp", t)
		if err != nil {
			log.Printf("Failed to resolve target address %s: %v", target, err)
			continue
		}

		go func(data []byte, remote net.Addr) {
			targetConn, err := net.DialUDP("udp", nil, targetAddr)
			if err != nil {
				log.Printf("Failed to connect to target %s: %v", target, err)
				return
			}
			defer targetConn.Close()

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
		}(buffer[:n], remoteAddr)
	}
}

func fixKey(key string) string {
	// Remove any whitespace
	key = strings.TrimSpace(key)

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Fatal("Error decoding base64:", err)
	}

	// Convert to hex
	return hex.EncodeToString(decoded)
}

func ping(tnet *netstack.Net, dst string) {
	socket, err := tnet.Dial("ping4", dst)
	if err != nil {
		log.Panic(err)
	}
	requestPing := icmp.Echo{
		Seq:  rand.Intn(1 << 16),
		Data: []byte("gopher burrow"),
	}
	icmpBytes, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	socket.SetReadDeadline(time.Now().Add(time.Second * 10))
	start := time.Now()
	_, err = socket.Write(icmpBytes)
	if err != nil {
		log.Panic(err)
	}
	n, err := socket.Read(icmpBytes[:])
	if err != nil {
		log.Panic(err)
	}
	replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
	if err != nil {
		log.Panic(err)
	}
	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		log.Panicf("invalid reply type: %v", replyPacket)
	}
	if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
		log.Panicf("invalid ping reply: %v", replyPing)
	}
	log.Printf("Ping latency: %v", time.Since(start))
}

func main() {
	var (
		tunnelIP   string
		privateKey string
		publicKey  string
		endpoint   string
		tcpTargets string
		udpTargets string
		listenIP   string
		serverIP   string
		dns        string
	)

	flag.StringVar(&tunnelIP, "tunnel-ip", "", "Tunnel IP address")
	flag.StringVar(&privateKey, "private-key", "", "WireGuard private key")
	flag.StringVar(&publicKey, "public-key", "", "WireGuard public key")
	flag.StringVar(&endpoint, "endpoint", "", "WireGuard endpoint (host:port)")
	flag.StringVar(&tcpTargets, "tcp-targets", "", "Comma-separated list of TCP targets (host:port)")
	flag.StringVar(&udpTargets, "udp-targets", "", "Comma-separated list of UDP targets (host:port)")
	flag.StringVar(&listenIP, "listen-ip", "", "IP to listen for incoming connections")
	flag.StringVar(&serverIP, "server-ip", "", "IP to filter and ping on the server side. Inside tunnel...")
	flag.StringVar(&dns, "dns", "8.8.8.8", "DNS server to use")

	flag.Parse()

	// Create TUN device and network stack
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(tunnelIP)},
		[]netip.Addr{netip.MustParseAddr(dns)},
		1420)
	if err != nil {
		log.Panic(err)
	}

	// Create WireGuard device
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))

	// Configure WireGuard
	config := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s
persistent_keepalive_interval=5
`, fixKey(privateKey), fixKey(publicKey), serverIP, endpoint)

	err = dev.IpcSet(config)
	if err != nil {
		log.Panic(err)
	}

	// Bring up the device
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}

	// Ping to bring the tunnel up on the server side quickly
	ping(tnet, serverIP)

	// Create proxy manager
	pm := NewProxyManager(tnet)

	// Add TCP targets
	if tcpTargets != "" {
		targets := strings.Split(tcpTargets, ",")
		pm.AddTarget("tcp", listenIP, targets)
	}

	// Add UDP targets
	if udpTargets != "" {
		targets := strings.Split(udpTargets, ",")
		pm.AddTarget("udp", listenIP, targets)
	}

	// Start proxies
	err = pm.Start()
	if err != nil {
		log.Panic(err)
	}

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Cleanup
	dev.Close()
}
