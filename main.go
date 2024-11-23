package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/netip"
	"newt/logger"
	"newt/proxy"
	"newt/websocket"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgData struct {
	Endpoint  string        `json:"endpoint"`
	PublicKey string        `json:"publicKey"`
	ServerIP  string        `json:"serverIP"`
	TunnelIP  string        `json:"tunnelIP"`
	Targets   TargetsByType `json:"targets"`
}

type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

type TargetData struct {
	Targets []string `json:"targets"`
}

func fixKey(key string) string {
	// Remove any whitespace
	key = strings.TrimSpace(key)

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		logger.Fatal("Error decoding base64:", err)
	}

	// Convert to hex
	return hex.EncodeToString(decoded)
}

func ping(tnet *netstack.Net, dst string) {
	logger.Info("Pinging %s", dst)
	socket, err := tnet.Dial("ping4", dst)
	if err != nil {
		logger.Error("Failed to create ICMP socket: %v", err)
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
		logger.Error("Failed to write ICMP packet: %v", err)
	}
	n, err := socket.Read(icmpBytes[:])
	if err != nil {
		logger.Error("Failed to read ICMP packet: %v", err)
	}
	replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
	if err != nil {
		logger.Error("Failed to parse ICMP packet: %v", err)
	}
	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		logger.Error("invalid reply type: %v", replyPacket)
	}
	if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
		logger.Error("invalid ping reply: %v", replyPing)
	}
	logger.Info("Ping latency: %v", time.Since(start))
}

func parseLogLevel(level string) logger.LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return logger.DEBUG
	case "INFO":
		return logger.INFO
	case "WARN":
		return logger.WARN
	case "ERROR":
		return logger.ERROR
	case "FATAL":
		return logger.FATAL
	default:
		return logger.INFO // default to INFO if invalid level provided
	}
}

func mapToWireGuardLogLevel(level logger.LogLevel) int {
	switch level {
	case logger.DEBUG:
		return device.LogLevelVerbose
	// case logger.INFO:
	// return device.LogLevel
	case logger.WARN:
		return device.LogLevelError
	case logger.ERROR, logger.FATAL:
		return device.LogLevelSilent
	default:
		return device.LogLevelSilent
	}
}

func main() {
	var (
		endpoint   string
		id         string
		secret     string
		dns        string
		privateKey wgtypes.Key
		err        error
		logLevel   string
	)

	flag.StringVar(&endpoint, "endpoint", "http://localhost:3000/api/v1", "Endpoint of your pangolin server")
	flag.StringVar(&id, "id", "", "Newt ID")
	flag.StringVar(&secret, "secret", "", "Newt secret")
	flag.StringVar(&dns, "dns", "8.8.8.8", "DNS server to use")
	flag.StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")

	flag.Parse()

	logger.Init()
	loggerLevel := parseLogLevel(logLevel)
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Fatal("Failed to generate private key: %v", err)
	}

	// Create a new client
	client, err := websocket.NewClient(
		// the id and secret from the params
		id,
		secret,
		websocket.WithBaseURL(endpoint), // TODO: save the endpoint in the config file so we dont have to pass it in every time
	)
	if err != nil {
		logger.Fatal("Failed to create client: %v", err)
	}

	// Create TUN device and network stack
	var tun tun.Device
	var tnet *netstack.Net
	var dev *device.Device
	var pm *proxy.ProxyManager
	var connected bool
	var wgData WgData

	// Register handlers for different message types
	client.RegisterHandler("newt/wg/connect", func(msg websocket.WSMessage) {
		if connected {
			logger.Info("Already connected! Put I will send a ping anyway...")
			ping(tnet, wgData.ServerIP)
			return
		}

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		logger.Info("Received: %+v", msg)
		tun, tnet, err = netstack.CreateNetTUN(
			[]netip.Addr{netip.MustParseAddr(wgData.TunnelIP)},
			[]netip.Addr{netip.MustParseAddr(dns)},
			1420)
		if err != nil {
			logger.Error("Failed to create TUN device: %v", err)
		}

		// Create WireGuard device
		dev = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(
			mapToWireGuardLogLevel(loggerLevel),
			"wireguard: ",
		))

		// Configure WireGuard
		config := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s
persistent_keepalive_interval=5`, fixKey(fmt.Sprintf("%s", privateKey)), fixKey(wgData.PublicKey), wgData.ServerIP, wgData.Endpoint)

		err = dev.IpcSet(config)
		if err != nil {
			logger.Error("Failed to configure WireGuard device: %v", err)
		}

		// Bring up the device
		err = dev.Up()
		if err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}

		logger.Info("WireGuard device created. Lets ping the server now...")
		// Ping to bring the tunnel up on the server side quickly
		ping(tnet, wgData.ServerIP)

		// Create proxy manager
		pm = proxy.NewProxyManager(tnet)

		connected = true

		// add the targets if there are any
		if len(wgData.Targets.TCP) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "tcp", TargetData{Targets: wgData.Targets.TCP})
		}

		if len(wgData.Targets.UDP) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "udp", TargetData{Targets: wgData.Targets.UDP})
		}
	})

	client.RegisterHandler("newt/tcp/add", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "tcp", targetData)
		}
	})

	client.RegisterHandler("newt/udp/add", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "udp", targetData)
		}
	})

	client.RegisterHandler("newt/udp/remove", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "remove", wgData.TunnelIP, "udp", targetData)
		}
	})

	client.RegisterHandler("newt/tcp/remove", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "remove", wgData.TunnelIP, "tcp", targetData)
		}
	})

	// Connect to the WebSocket server
	if err := client.Connect(); err != nil {
		logger.Fatal("Failed to connect to server: %v", err)
	}
	defer client.Close()

	publicKey := privateKey.PublicKey()
	logger.Info("Public key: %s", publicKey)
	// TODO: how to retry?
	err = client.SendMessage("newt/wg/register", map[string]interface{}{
		"publicKey": fmt.Sprintf("%s", publicKey),
	})
	if err != nil {
		logger.Info("Failed to send message: %v", err)
	}

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Cleanup
	dev.Close()
}

func parseTargetData(data interface{}) (TargetData, error) {
	var targetData TargetData
	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return targetData, err
	}

	if err := json.Unmarshal(jsonData, &targetData); err != nil {
		logger.Info("Error unmarshaling target data: %v", err)
		return targetData, err
	}
	return targetData, nil
}

func updateTargets(pm *proxy.ProxyManager, action string, tunnelIP string, proto string, targetData TargetData) error {
	for _, t := range targetData.Targets {
		// Split the first number off of the target with : separator and use as the port
		parts := strings.Split(t, ":")
		if len(parts) != 3 {
			logger.Info("Invalid target format: %s", t)
			continue
		}

		// Get the port as an int
		port := 0
		_, err := fmt.Sscanf(parts[0], "%d", &port)
		if err != nil {
			logger.Info("Invalid port: %s", parts[0])
			continue
		}

		if action == "add" {
			target := parts[1] + ":" + parts[2]
			// Only remove the specific target if it exists
			err := pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				// Ignore "target not found" errors as this is expected for new targets
				if !strings.Contains(err.Error(), "target not found") {
					logger.Error("Failed to remove existing target: %v", err)
				}
			}

			// Add the new target
			pm.AddTarget(proto, tunnelIP, port, target)

			// Start just this target by calling Start() on the proxy manager
			// The Start() function is idempotent and will only start new targets
			err = pm.Start()
			if err != nil {
				logger.Error("Failed to start proxy manager after adding target: %v", err)
				return err
			}
		} else if action == "remove" {
			logger.Info("Removing target with port %d", port)
			err := pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				logger.Error("Failed to remove target: %v", err)
				return err
			}
		}
	}

	return nil
}
