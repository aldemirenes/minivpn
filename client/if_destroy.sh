sudo ip addr del 10.0.3.3/24 dev tun0
sudo ip link del dev tun0 up
sudo ip tuntap del mode tun tun0