# MINIVPN

Proof-of-concept VPN implementation. Made for just learning
purposes and fun.

## Prerequisities:
* Vagrant

## Setup:
If you are not using vagrant provisioning, you should run 
`up.sh` scripts in the client and server folders in order 
to install dependencies. If you are using vagrant provisioning, 
all the dependecies will be installed automatically.

## Usage:
There are two folder in the main directory which is client
and server.
If you want to test the MiniVPN in your local,
you can use Vagrant provisioning
It is sufficient to go to the respective folder and run
`vagrant up` command in the respective folder. After vagrant
machine is started to run, you can connect to vagrant machine
with `vagrant ssh` command.
You should start server initially. After server is started, you
can connect to server with client.

## Server usage:
After connect to the vagrant machine with SSH, go to /vagrant
directory. When you check the files in this folder, you will 
see files which are under the server folder.
In the /vagrant directory, run `./dtls_server_init.sh` script.

## Client usage:
After connect to the vagrant machine with SSH, go to /vagrant
directory. When you check the files in this folder, you will 
see files which are under the client folder. 
In the /vagrant directory, run `./dtls_client_init.sh <server_ip>` script. 

## Testing the MiniVPN:
ping command can be used for whether or not VPN is started to succesfully.
You can ping 10.0.3.2 address from client. This is tun interface IP of the
server. If VPN is started successfully, you should get ping response as
expected. Also, if server VPN program is run in the different machine with
different public IP, client will have server public IP as its public IP.
You can check the public IP of the client with the `curl ipinfo.io/ip` command.
Also, you can use tcpdump tool in order to verify communication is enrcrypted.

**NOTE**:
If you are running server or client other machines than vagrant
machines which is configured beforehand, you should change path
of the SSL certificate and key file in the init scripts.

Some of the parts of the following projects are used in the MiniVPN:
* http://backreference.org/2010/03/26/tuntap-interface-tutorial/
* https://github.com/nplab/DTLS-Examples

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details