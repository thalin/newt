package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/netip"
	"newt/proxy"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

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
	pm := proxy.NewProxyManager(tnet)

	// Add TCP targets
	if tcpTargets != "" {
		targets := strings.Split(tcpTargets, ",")
		for _, t := range targets {
			// Split the first number off of the target with : separator and use as the port
			parts := strings.Split(t, ":")
			if len(parts) != 2 {
				log.Panicf("Invalid target: %s", t)
			}
			// get the port as a int
			port := 0
			_, err := fmt.Sscanf(parts[0], "%d", &port)
			if err != nil {
				log.Panicf("Invalid port: %s", parts[0])
			}
			target := parts[1]
			pm.AddTarget("tcp", listenIP, port, target)
		}
	}

	// Add UDP targets
	if udpTargets != "" {
		targets := strings.Split(udpTargets, ",")
		for _, t := range targets {
			// Split the first number off of the target with : separator and use as the port
			parts := strings.Split(t, ":")
			if len(parts) != 2 {
				log.Panicf("Invalid target: %s", t)
			}
			// get the port as a int
			port := 0
			_, err := fmt.Sscanf(parts[0], "%d", &port)
			if err != nil {
				log.Panicf("Invalid port: %s", parts[0])
			}
			target := parts[1]
			pm.AddTarget("udp", listenIP, port, target)
		}
	}

	// Start proxies
	err = pm.Start()
	if err != nil {
		log.Panic(err)
	}

	url := "ws://localhost/api/v1/ws"
	token := "your-auth-token"

	if err := websocket.connectWebSocket(url, token); err != nil {
		log.Fatalf("WebSocket error: %v", err)
	}

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Cleanup
	dev.Close()
}
