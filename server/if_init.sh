#! /bin/sh

sudo ip tuntap add mode tun tun0
sudo ip link set dev tun0 up
sudo ip addr add 10.0.3.2/24 dev tun0

sudo echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT