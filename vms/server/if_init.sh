sudo ip tuntap add mode tun tun0
sudo ip link set dev tun0 up
sudo ip addr add 10.0.3.2/24 dev tun0