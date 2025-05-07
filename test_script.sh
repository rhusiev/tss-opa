#!/bin/bash

INTERFACE="lo"
TEST_PORT="1337"
WRONG_PORT="1338"
TEST_IP="127.0.0.1"
MESSAGE="Hello, XDP firewall!"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "Detaching any existing XDP programs..."
./bin/xdp-firewall -D "$INTERFACE" -S

echo -e "\n== Loading XDP =="
./bin/xdp-firewall "$INTERFACE" "$TEST_PORT" -S
if [ $? -ne 0 ]; then
  echo "Failed to load XDP program. Exiting."
  exit 1
fi

echo -e "\n== Starting tcpdump =="
tcpdump -i "$INTERFACE" -n -vv host "$TEST_IP" -A &
TCPDUMP_PID=$!

sleep 1

echo -e "\n== Sending packet with the correct signature. Expect some tcpdump info after it =="
./bin/packet_sender "$TEST_IP" "$TEST_PORT" "$MESSAGE"

sleep 1

echo -e "\n== Sending packet without a signature. Expect no tcpdump info after it =="
echo "hello" | nc -u -w 1 $TEST_IP $TEST_PORT

sleep 1

echo -e "\n== Sending packet with wrong port and right signature. Expect no tcpdump info after it =="
./bin/packet_sender "$TEST_IP" "$WRONG_PORT" "$MESSAGE"

echo -e "\n== Cleaning up =="
kill $TCPDUMP_PID 2>/dev/null
./bin/xdp-firewall -D "$INTERFACE" -S
