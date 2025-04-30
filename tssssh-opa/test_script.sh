#!/bin/bash

INTERFACE="lo"
CORRECT_PASSWORD="AABBCCDDEEFF11223344556677889900"
WRONG_PASSWORD="0102030405060708090A0B0C0D0E0F10"
TEST_PORT="1337"
WRONG_PORT="1338"
TEST_IP="127.0.0.1"
MESSAGE="Hello, XDP firewall!"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "Detaching any existing XDP programs..."
./xdp-firewall -D "$INTERFACE" -S

echo -e "\n== Loading XDP =="
./xdp-firewall -p "$CORRECT_PASSWORD" "$INTERFACE" "$TEST_PORT" -S
if [ $? -ne 0 ]; then
  echo "Failed to load XDP program. Exiting."
  exit 1
fi

echo -e "\n== Starting tcpdump =="
tcpdump -i "$INTERFACE" -n -vv host "$TEST_IP" &
TCPDUMP_PID=$!

sleep 1

echo -e "\n== Sending packet with correct password. Expect some tcpdump info after it =="
./packet_sender -p "$CORRECT_PASSWORD" "$TEST_IP" "$TEST_PORT" "$MESSAGE"

sleep 1

echo -e "\n== Sending packet with wrong password. Expect no tcpdump info after it =="
./packet_sender -p "$WRONG_PASSWORD" "$TEST_IP" "$TEST_PORT" "$MESSAGE"

sleep 1

echo -e "\n== Sending packet with wrong port and right password. Expect no tcpdump info after it =="
./packet_sender -p "$CORRECT_PASSWORD" "$TEST_IP" "$WRONG_PORT" "$MESSAGE"

echo -e "\n== Cleaning up =="
kill $TCPDUMP_PID 2>/dev/null
./xdp-firewall -D "$INTERFACE" -S
