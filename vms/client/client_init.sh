./if_destroy.sh
./if_init.sh
cd simpletun
make all
sudo ./client -i tun0 -s 10.10.1.2 -p 5555 -u -d