#!/bin/bash
WIFICARD=$1
 
IP_ADDR=`ifconfig $WIFICARD | grep "inet " | awk '{print $2}'`
ETHER_ADDR=`ifconfig $WIFICARD | grep "ether " | awk '{print $2}'`

OUTPUT_FILE="ld-pcap.pcap"
 
# Change ownership of output file
touch $OUTPUT_FILE
 
# Ignore these non-data wifi packets
#   802.11 probe request   0x40
#   802.11 probe response  0x50
#   802.11 beacon          0x80
#   802.11 "power save"    0xA4
#   802.11 "clear to send" 0xC4
#   802.11 ACK frame       0xD4
#
# See http://www.nersc.gov/~scottc/misc/docs/snort-2.1.1-RC1/decode_8h-source.html for more.
echo "Press ctrl-c to quit."

sudo tcpdump \
    -i $WIFICARD \
    -I \
    -n \
    -w $OUTPUT_FILE \
    not "(wlan[0:1] & 0xfc) == 0x40" \
    and not "(wlan[0:1] & 0xfc) == 0x50" \
    and not "(wlan[0:1] & 0xfc) == 0x80" \
    and not "(wlan[0:1] & 0xfc) == 0xa4" \
    and not "(wlan[0:1] & 0xfc) == 0xc4" \
    and not "(wlan[0:1] & 0xfc) == 0xd4" \
    # and not ether host $ETHER_ADDR \
    # and not host $IP_ADDR \
    # and not "(wlan[0:1] & 0xfc) == 0x7c" \
    # and not "(wlan[0:1] & 0xfc) == 0x69" \

airdecap-ng $OUTPUT_FILE