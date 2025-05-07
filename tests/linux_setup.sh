sudo sysctl net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.42.0.0/24 -o Privex -j MASQUERADE
sudo iptables -A FORWARD -i enp3s0 -o Privex -s 10.42.0.0/24 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i Privex -o enp3s0 -m state --state RELATED,ESTABLISHED -j ACCEPT

sudo ./bin/packet_sender 10.42.0.114 1337 "Hi" -s 10.42.0.1
