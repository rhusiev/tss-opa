# TimeStamp Synchronized Open Port Authentication (TSS-OPA)

When cloning, do it with submodules:

```sh
git clone --recursive https://github.com/ucu/sec/tss-opa
# if unsuccessful, procede with
git submodule update --init --recursive
```

You might need these packages:

```sh
sudo apt install libelf-dev clang libbfd-dev llvm libcap-dev
```

Or equivalent ones in your distro

Then do

```sh
cd tss-opa
make
cd ../password_packet_sender
make
```

Then run

```sh
sh ./test_script.sh
```

to test. It will guide you, what the output should be.

To run custom messages, run on server:

```sh
./bin/xdp-firewall <NETWORK INTERFACE> <PORT1> [... other ports] -S
tcpdump -i <NETWORK INTERFACE> -n -vv host <CLIENT IP> & # We set host, so that there is not a huge stream of other packets
```

and on the client:

```sh
./bin/packet_sender <SERVER IP> <PORT> <MESSAGE> [-s <CLIENT IP>] # client ip needed if you are sending outside of localhost
```
