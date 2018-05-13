#! /bin/sh

remote_ip=$1

./if_destroy.sh
./if_init.sh
cd dtls_client
make clean
make all
# sudo ./client -i tun0 -s 10.10.1.2 -p 23232 -c /vagrant/cert.pem -k /vagrant/key.pem
sudo ./client -i tun0 -s $1 -p 23232 -c /vagrant/cert.pem -k /vagrant/key.pem