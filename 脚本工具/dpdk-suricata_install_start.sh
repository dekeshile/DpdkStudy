#! /bin/bash

# dpdk-suricata安装并启动脚本
# 使用说明

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

       # remove_igb_uio_module

       #先看uio模块是否之前被加载过，没加载过才进行加载
        /sbin/lsmod | grep -s uio > /dev/null
        if [ $? -ne 0 ] ; then
                modinfo uio > /dev/null
                if [ $? -eq 0 ]; then
                        echo "Loading uio module"
                        sudo /sbin/modprobe uio   #载入模块uio,modprobe命令可以自动搜索、加载链接 
                fi
        fi

        #先看 igb_uio 模块是否之前被加载过，没加载过才进行加载
        #并且先解绑igb_uio绑定的网卡，将其邦回igb驱动
        /sbin/lsmod | grep -s igb_uio > /dev/null
        if [ $? -ne 0 ] ;
        then
            echo "Loading DPDK UIO module"
            sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko     #载入模块igb_uio.ko 
            if [ $? -ne 0 ] ; then
                echo "## ERROR: Could not load kmod/igb_uio.ko."
                quit
            fi
        else
            #绑回linux内核
            bind_back_kenel
        fi   
}

bind_back_kenel()
{
        #找到没有被    [内核驱动]  和  [] igb_uio驱动]   绑定的网卡
        igbuio_device=$( $RTE_SDK/usertools/dpdk-devbind.py  -s | grep drv=igb_uio | awk '{print $1}')
        for  rci in $igbuio_device
        do
	$RTE_SDK/usertools/dpdk-devbind.py -b $host_drive  $rci #绑回linux内核
        done
}

#因脚本中执行异常，恢复为原来的环境
restore_env()
{
    echo "restore previous enviroment"
    clear_huge_pages
    bind_back_kenel
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


#--------------------步骤从这里开始-------------------------------------------------------

#不要进行选项 要进行傻瓜式的检查
# 第一次编译，并且直接使用 安装dpdk和suricata
# 步骤：
#  1.检查是否有dpdk进程正在运行
#  2.检查是否有suricata进程正在运行
#  3.先安装好dpdk
#       1).设置dpdk环境变量
#       1).编译安装dpdk
#       2).设置大叶内存
#       3).启用UIO
#       4).绑定网卡到驱动igb_uio上
#  4.安装sricata
#  5.启动dpdk-suricata
#
#
#

#---------------检查是否有dpdk进程正在运行---------------
dpdk_pid=$(ps -ef |grep dpdk |grep -v grep | awk '{print $2}')
if [ -n "$dpdk_pid" ]; 
then
   echo "dpdk process is running [$dpdk_pid]"
else
   echo "start make dpdk........................."
fi


#---------------编译安装dpdk start----------------------------------------------------

#dpdk工作路径
dpdk_wkdir=/home/wurp

#设置环境变量
RTE_SDK=${dpdk_wkdir}/dpdk-stable-19.11.1
export RTE_SDK
RTE_TARGET=x86_64-native-linuxapp-gcc
export RTE_TARGET 


#多核编译安装dpdk
make -j install T=${RTE_TARGET}
if [ $? -ne 0 ] 
then
    echo "Something error when make dpdk, exit"
    exit
fi


#设置大叶内存
HUGEPGSZ=$(cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' ')
set_non_numa_pages

#启用igb_uio模块,并解绑原绑定igb_uio的所有网卡
host_drive=igb
load_igb_uio_module

#需要绑定到 igb_uio 的网卡
need_binds=(eth5 eth6)

#检查是否存在这个网卡,存在则将其绑定igb_uio,不存在则退出
for net_name in ${need_binds[@]};do
    no_bind=$($RTE_SDK/usertools/dpdk-devbind.py --status | grep $net_name)
    if [ $no_bind -eq 0 ]
    then
        ifconfig $net_name down  #先关闭网卡
        $RTE_SDK/usertools/dpdk-devbind.py --bind=igb_uio $net_name #绑定UIO模块到网卡
    else
        echo "can not find Interface:$net_name,Please check it"
        #因脚本中执行异常，恢复为原来的环境
        restore_env
        exit
    fi
done


#验证网卡绑定igb_uio的情况
for net_name in ${need_binds[@]};do
    suc=$($RTE_SDK/usertools/dpdk-devbind.py --status | grep "if=$net_name drv=igb_uio")
    if [ $suc -eq 0 ] ; then
        echo "bind $net_name succuss !!"
    else
        echo "something error when bind Interface:$net_name ,check it "
        #因脚本中执行异常，恢复为原来的环境
        restore_env
        exit
    fi
done
