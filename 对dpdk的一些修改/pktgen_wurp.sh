#!/bin/sh
# pktgen.conf -- Sample configuration for send on two devices on a UP system

#modprobe pktgen

if [[ `lsmod | grep pktgen` == "" ]];then
   modprobe pktgen
fi

if [[ $1 == "" ]];then
   pktsize=550
else
   pktsize=$1
fi

function pgset() {
    local result

    echo $1 > $PGDEV

    result=`cat $PGDEV | fgrep "Result: OK:"`
    if [ "$result" = "" ]; then
         cat $PGDEV | fgrep Result:
    fi
}

function pg() {
    echo inject > $PGDEV
    cat $PGDEV
}

# On UP systems only one thread exists -- so just add devices
# We use eth1, eth1

echo "Adding devices to run".

PGDEV=/proc/net/pktgen/kpktgend_0
pgset "rem_device_all"
pgset "add_device eth1"
pgset "max_before_softirq 1"

# Configure the individual devices
echo "Configuring devices"

PGDEV=/proc/net/pktgen/eth1

pgset "clone_skb 1000"
pgset "pkt_size $pktsize"
pgset "src_mac 00:1B:21:90:4B:E4"
pgset "flag IPSRC_RND"
pgset "src_min 10.0.0.2"
pgset "src_max 10.0.0.255"
pgset "dst 192.168.2.37"
pgset "dst_mac C4:00:AD:48:E1:8B"
pgset "count 0"

# Time to run

PGDEV=/proc/net/pktgen/pgctrl
echo "pkgsize:$pktsize"
echo "Running... ctrl^C to stop"

pgset "start"

echo "Done"
