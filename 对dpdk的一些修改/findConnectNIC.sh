#!/bin/bash

network=(eth0 eth1 eth2 eth3 eth4 eth5 eth6 eth7 eth8 eth9 eth10 eth11 eth12  eth14 eth15 eth16 eth17 eth18 eth19 \
eth20 eth21 eth22 eth23 eth0.12 eth19.1 eth3.1  eth6.3)

for net in ${network[@]};
do
{
    tcpreplay -i $net -l 100 /home/wurp/tcpdump.pcap
} &
done
wait
date