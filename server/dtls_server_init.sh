#! /bin/sh

./if_destroy.sh
./if_init.sh
cd dtls_server
make clean
make all
./server -i tun0 -p 23232 -c /vagrant/cert.pem -k /vagrant/key.pem