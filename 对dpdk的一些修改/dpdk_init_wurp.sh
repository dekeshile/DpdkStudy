#!/bin/bash

HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`

#
# Unloads igb_uio.ko.
#
remove_igb_uio_module()
{
        echo "Unloading any existing DPDK UIO module"
        /sbin/lsmod | grep -s igb_uio > /dev/null
        if [ $? -eq 0 ] ; then
                sudo /sbin/rmmod igb_uio
        fi
}

#
# Loads new igb_uio.ko (and uio module if needed).
#
load_igb_uio_module()
{
        if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko ];then
                echo "## ERROR: Target does not have the DPDK UIO Kernel Module."
                echo "       To fix, please try to rebuild target."
                return
        fi

        remove_igb_uio_module

        /sbin/lsmod | grep -s uio > /dev/null
        if [ $? -ne 0 ] ; then
                modinfo uio > /dev/null
                if [ $? -eq 0 ]; then
                        echo "Loading uio module"
                        sudo /sbin/modprobe uio
                fi
           fi

        # UIO may be compiled into kernel, so it may not be an error if it can't
        # be loaded.

        echo "Loading DPDK UIO module"
        sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko
        if [ $? -ne 0 ] ; then
                echo "## ERROR: Could not load kmod/igb_uio.ko."
                quit
        fi
}

#
# Removes hugepage filesystem.
#
remove_mnt_huge()
{
	echo "Unmounting /mnt/huge and removing directory"
	grep -s '/mnt/huge' /proc/mounts > /dev/null
	if [ $? -eq 0 ] ; then
		sudo umount /mnt/huge
	fi

	if [ -d /mnt/huge ] ; then
		sudo rm -R /mnt/huge
	fi
}

#
# Removes all reserved hugepages.
#
clear_huge_pages()
{
	echo > .echo_tmp
	for d in /sys/devices/system/node/node? ; do
		echo "echo 0 > $d/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" >> .echo_tmp
	done
	echo "Removing currently reserved hugepages"
	sudo sh .echo_tmp
	rm -f .echo_tmp

	remove_mnt_huge
}

#
# Creates hugepage filesystem.
#
create_mnt_huge()
{
	echo "Creating /mnt/huge and mounting as hugetlbfs"
	sudo mkdir -p /mnt/huge

	grep -s '/mnt/huge' /proc/mounts > /dev/null
	if [ $? -ne 0 ] ; then
		sudo mount -t hugetlbfs nodev /mnt/huge
	fi
}


set_non_numa_pages()
{
	clear_huge_pages
	Pages=512
	echo "echo $Pages > /sys/kernel/mm/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" > .echo_tmp
	echo "Reserving hugepages"
	sudo sh .echo_tmp
	rm -f .echo_tmp
	create_mnt_huge
}


#设置环境变量
export RTE_SDK=/home/wurp/dpdk-stable-19.11.1
export RTE_TARGET=x86_64-native-linuxapp-gcc



#编译安装dpdk
make_order=makeinstall
if [ "" !=  "$1" ]; then
  echo "param is $1"
  if [ "$make_order" = "$1" ]; then
    echo "begin make install"
    make install T=${RTE_TARGET}
  else
     echo "not param:makeinstall"
 fi
else
  echo "jump over make install"
fi


#设置大叶内存
set_non_numa_pages


#启用UIO
load_igb_uio_module

host_drive=igb

#找到没有被    [内核驱动]  和  [] igb_uio驱动]   绑定的网卡
other_device=$( $RTE_SDK/usertools/dpdk-devbind.py  -s | grep unused=$host_drive,igb_uio | awk '{print $1}')
for  rci in $other_device
do
	echo bind $rci back to   kernel driver
	 $RTE_SDK/usertools/dpdk-devbind.py -b $host_drive  $rci #绑回linux内核
done

#需要绑定到UIO的网卡
need_binds=(eth5 eth6)

for net_name in ${need_binds[@]};do
    #被内核驱动绑定但还没有绑定UIO模块的网卡
    echo "net_name:$net_name"
    no_bind=$($RTE_SDK/usertools/dpdk-devbind.py --status | grep $net_name)
    echo "$no_bind"
		if [ -n "$no_bind" ]
		then
			echo "$net_name have not bind"
			ifconfig $net_name down  #先关闭网卡
			$RTE_SDK/usertools/dpdk-devbind.py --bind=igb_uio $net_name #绑定UIO模块到网卡
    	echo "bind igb_uio $net_name"
    else
        echo "can not find $net_name"
		fi
done


#进行验证查看网卡绑定情况
$RTE_SDK/usertools/dpdk-devbind.py --status   

