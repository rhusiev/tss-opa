sudo apt install libelf-dev clang libbfd-dev llvm libcap-dev

sudo ip route add default via 10.42.0.1 dev eth0

sudo tcpdump -i eth0 -n -vv "not (port 49986) and host 10.42.0.1" # 49986 - a random port that has lots of traffic. probably will be different each time
