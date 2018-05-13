#! /bin/sh

remote_ip=$1

sudo ip tuntap add mode tun tun0
sudo ip link set dev tun0 up
sudo ip addr add 10.0.3.3/24 dev tun0

sudo route add -net $remote_ip gw 10.0.2.2 netmask 255.255.255.255 dev eth0
sudo route del -net 0.0.0.0 gw 10.0.2.2 netmask 0.0.0.0 dev eth0
sudo route add default gw 10.0.3.3