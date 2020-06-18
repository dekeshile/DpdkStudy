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
        #先看 igb_uio 模块是否之前被加载过，没加载过才进行加载
        #并且先解绑igb_uio绑定的网卡，将其邦回igb驱动
        /sbin/lsmod | grep -s igb_uio > /dev/null
        if [ $? -eq 0 ] ;
        then
              #绑回linux内核
            bind_back_kenel
            return
        fi   

         #是否有igb_uio.ko模块
        if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko ];then
                echo "## ERROR: Target does not have the DPDK UIO Kernel Module."
                echo "       To fix, please try to rebuild target."
                return
        fi

       #先看uio模块是否之前被加载过，没加载过才进行加载
        /sbin/lsmod | grep -s uio > /dev/null
        if [ $? -ne 0 ] ; then
                modinfo uio > /dev/null
                if [ $? -eq 0 ]; then
                        echo "Loading uio module"
                        sudo /sbin/modprobe uio   #载入模块uio,modprobe命令可以自动搜索、加载链接 
                fi
        fi

        echo "Loading DPDK UIO module"
        sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko     #载入模块igb_uio.ko 
        if [ $? -ne 0 ] ; then
            echo "## ERROR: Could not load kmod/igb_uio.ko."
            quit
        fi
}

#
# Loads new rte_kni.ko 
#
load_kni_module()
{
        #检查是是否有rte_kni.ko这个模块
        if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/rte_kni.ko  ];then
                echo "## ERROR: Target does not have the DPDK KNI Module."
                echo "       To fix, please try to rebuild target."
                return
        fi

        #先看 kni 模块是否之前被加载过，没加载过才进行加载
        /sbin/lsmod | grep -s rte_kni > /dev/null
        if [ $? -ne 0 ] ;
        then
            echo "Loading DPDK KNI module"
            sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/rte_kni.ko kthread_mode=multiple    #载入模块rte_kni.ko
            if [ $? -ne 0 ] ; then
                echo "## ERROR: Could not load kmod/rte_kni.ko."
                quit
            fi
        fi
}

bind_back_kenel()
{
        #找到没有被  [内核驱动igb] 和 [igb_uio驱动]   绑定的网卡
        nodrive_net=$( $RTE_SDK/usertools/dpdk-devbind.py  -s | grep unused=igb,igb_uio  | awk '{print $1}')
        for  echo_net in $nodrive_net
        do
	        $RTE_SDK/usertools/dpdk-devbind.py -b $HOST_DRIVE  $echo_net #绑回linux内核
        done

        #找到已经绑定 [igb_uio驱动] 网卡，将其绑回内核
        igbuio_device=$( $RTE_SDK/usertools/dpdk-devbind.py  -s | grep drv=igb_uio | awk '{print $1}')
        for  rci in $igbuio_device
        do
	        $RTE_SDK/usertools/dpdk-devbind.py -b $HOST_DRIVE  $rci #绑回linux内核
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
# 需准备好的文件
#   igb_UIO模块 kmod/igb_uio.ko  
#   KNI模块  kmod/rte_kni.ko
#  可执行程序  dpdk-kni


# 部署并运行dpdk和suricata
# 步骤：
#  1.检查是否有dpdk进程正在运行
#  2.检查是否有suricata进程正在运行
#  3.dpdk环境部署
#       1).设置dpdk环境变量
#       2).设置大叶内存
#       3).启用igb_uio模块,启用KNI模块
#       4).绑定网卡到驱动igb_uio上
#  4.启动dpdk-kni程序
#  5.启动sricata程序
#
#
#  网卡本来绑定好igb_uio的网卡的，但是还没解绑，就又把igb_uio卸载，这时候原本的网卡会丢失驱动，导致unused=igb,igb_uio 
#---------------检查是否有dpdk进程正在运行---------------


dpdk_pid=$(ps -ef |grep dpdk |grep -v grep | awk '{print $2}')
if [ -n "$dpdk_pid" ]; 
then
   echo "dpdk process is running [$dpdk_pid]"
   echo "if you want restart please run stop-dpdk-suricata.sh,then run this"
else
   echo "start set dpdk   enviroment........................."
fi

#--------------set dpdk enviroment start----------------------------------------------------

#dpdk工作路径
dpdk_wkdir=/home/wurp

#设置环境变量
RTE_SDK=${dpdk_wkdir}/dpdk-stable-19.11.1
export RTE_SDK
RTE_TARGET=x86_64-native-linuxapp-gcc
export RTE_TARGET 


#设置大叶内存
HUGEPGSZ=$(cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' ')
set_non_numa_pages

#启用igb_uio模块,并解绑原绑定igb_uio的所有网卡
HOST_DRIVE=igb
load_igb_uio_module

#需要绑定到 igb_uio 的网卡
need_binds=(eth5 eth6)


#检查是否存在这个网卡,存在则将其绑定igb_uio,不存在则退出
for net_name in ${need_binds[@]};do
    ifconfig | grep $net_name
    if [ $? -eq 0 ]
    then
        ifconfig $net_name down  #先关闭网卡
         #绑定UIO模块到网卡
         /home/wurp/dpdk-stable-19.11.1/usertools/dpdk-devbind.py --bind=igb_uio $net_name
        echo "exec bind  net done"
    else
        echo "can not find Interface:$net_name,Please check it"
        #因脚本中执行异常，恢复为原来的环境
        restore_env
        exit
    fi
done


#验证网卡绑定igb_uio的情况
for net_name in ${need_binds[@]};do
   # $RTE_SDK/usertools/dpdk-devbind.py --status | grep "if=$net_name drv=igb"
    ifconfig | grep $net_name
    if [ $?  -eq 0 ] ; then
         echo "something error when bind Interface:$net_name ,check it "
        #因脚本中执行异常，恢复为原来的环境
        restore_env
        exit
    else
       echo "bind $net_name succuss !!"
    fi
done

#启用kni模块
load_kni_module

#启动dpdk程序
make /home/wurp/dpdk-stable-19.11.1/examples/l3-kni.mengbo/l3-kni

if [ $? -ne 0 ] ; then
        echo "-----------make failed"
		restore_env
        exit
    else
        echo "-----------make success"
fi

chmod 777 /home/wurp/dpdk-stable-19.11.1/examples/l3-kni.mengbo/l3-kni/build/l3fwd
nohup  /home/wurp/dpdk-stable-19.11.1/examples/l3-kni.mengbo/l3-kni/build/l3fwd > dpdk.log 2>&1 &

#dpdk没有启动成功，返回非0
if [ $? -ne 0 ] ; then
        echo "-----------dpdk run failed"
		restore_env
        exit
fi

flag=0

#for i in `seq 1 100`
for i in $(seq 1 10) 
do
    #获取所有kni生成的网卡名，并把网卡名写入到suricata配置文件中
    kni_net=$(ifconfig -a | grep vEth | cut -d : -f 1 | tr -d ':')
    if [ -z  "$kni_net" ]; then
        sleep 1
    else
       flag=1
       echo "find kni_net"
       echo $kni_net
       break
    fi
done

if [ $flag -eq 0 ]; then
    echo "can't find kni_net , quit"
    exit
fi


#将虚拟网卡启动起来
for each_net in $kni_net
do
    ifconfig $each_net up
done

pcapYaml="/usr/c_app/suricata/etc/pcap_dpdk.yaml"
# 判断pcap.yaml 是否存在
if [ ! -f "$pcapYaml" ]; then
 touch "$pcapYaml"
fi

#写入pcap.yaml文件
#先清空pcap.yaml文件
echo "" >  $pcapYaml
echo "pcap:" >> $pcapYaml
for line in $kni_net
do 
    echo "- interface: $line" >> $pcapYaml
    echo "- buffer-size: 134217728" >> $pcapYaml
    echo "- threads: auto" >> $pcapYaml
done

#---------------suricata start----------------------------------------------------
suricata_pid=`ps -ef |grep suricata |grep -v grep|grep -v "start_suricata" | awk '{print $2}'`
if [ ! -z "$suricata_pid" ]; 
then
   echo "suricata process is running [$suricata_pid]"
else
   echo "start suricata process..."
   rm -rf /datadb/suricata/run/suricata.pid
   /usr/c_app/suricata/suricata -c /usr/c_app/suricata/etc/suricata.yaml --pidfile /datadb/suricata/run/suricata.pid --pcap -D

fi