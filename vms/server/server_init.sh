./if_destroy.sh
./if_init.sh
cd simpletun
make all
./server -i tun0 -p 5555 -u -d