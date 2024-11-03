ip link add dev wg0 type wireguard
ip addr add 192.168.4.1/24 dev wg0
ip link set up dev wg0
wg set wg0 private-key ./key
wg set wg0 listen-port 51820
wg set wg0 peer 3QfirSdDVihYCAz66t6DTAtFtsh+9WVVu7ItlL750hI= allowed-ips 192.168.4.28