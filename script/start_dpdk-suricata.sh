#! /bin/bash

# dpdk-suricata安装启动脚本
# 使用说明
# 需准备好的文件
#   igb_UIO模块 kmod/igb_uio.ko  
#   KNI模块  kmod/rte_kni.ko
#  可执行程序  dpdk-kni
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

#---------------------------全局参数定义 start-------------------------------------------------------------------
#dpdk运行的程序名称
DPDK_APP_NAME=dpdk-capture

#操作系统默认的网卡驱动
HOST_DRIVE=igb

#需要绑定到 igb_uio 的网卡
#physics_net=(eth5 eth6)

#从配置文件里读取dpdk使用的物理网卡 
read_pcap_yaml="/usr/c_app/suricata/etc/pcap_test_read.yaml"

#DPDK程序里配置的一个物理队列对应的队列数
DPDK_CONFIG_QUEUE=6

#dpdk-kni生成的虚拟网卡写入的文件
pcapYaml="/usr/c_app/suricata/etc/pcap_dpdk.yaml"


#---------------------------全局参数定义 end-------------------------------------------------------------------




#-----------------------------一些函数定义 start-------------------------------------------------------------------

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
        if [ ! -f ./kmod/igb_uio.ko ];then
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
        sudo /sbin/insmod ./kmod/igb_uio.ko     #载入模块igb_uio.ko 
        if [ $? -ne 0 ] ; then
            echo "## ERROR: Could not load kmod/igb_uio.ko."
            restore_env
            quit
        fi
}

#
# Loads new rte_kni.ko 
#
load_kni_module()
{
        #检查是是否有rte_kni.ko这个模块
        if [ ! -f ./kmod/rte_kni.ko  ];then
                echo "## ERROR: Target does not have the DPDK KNI Module."
                echo "       To fix, please try to rebuild target."
                return
        fi

        #先看 kni 模块是否之前被加载过，没加载过才进行加载
        /sbin/lsmod | grep -s rte_kni > /dev/null
        if [ $? -ne 0 ] ;
        then
            echo "Loading DPDK KNI module"
            sudo /sbin/insmod ./kmod/rte_kni.ko kthread_mode=multiple    #载入模块rte_kni.ko
            if [ $? -ne 0 ] ; then
                echo "## ERROR: Could not load kmod/rte_kni.ko."
                restore_env
                quit
            fi
        fi
}

bind_back_kenel()
{
        #找到没有被  [内核驱动igb] 和 [igb_uio驱动]   绑定的网卡
        nodrive_net=$( ./usertools/dpdk-devbind.py  -s | grep unused=igb,igb_uio  | awk '{print $1}')
        for  echo_net in $nodrive_net
        do
	        ./usertools/dpdk-devbind.py -b $HOST_DRIVE  $echo_net #绑回linux内核
        done

        #找到已经绑定 [igb_uio驱动] 网卡，将其绑回内核
        igbuio_device=$( ./usertools/dpdk-devbind.py  -s | grep drv=igb_uio | awk '{print $1}')
        for  rci in $igbuio_device
        do
	        ./usertools/dpdk-devbind.py -b $HOST_DRIVE  $rci #绑回linux内核
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

function loop_exe()
{
    local ex_count=0
    CMDLINE=$1
    while true ; do
        #command
        sleep 1
        echo The command is \"$CMDLINE\"
        ${CMDLINE}
        if [ $? == 0 ] ; then
            echo The command execute OK!
            break;
        else
            (( ex_count = ${ex_count} + 1 ))
            echo ERROR : The command execute fialed! ex_count = ${ex_count}.
        fi
    done
}

#编译dpdk
make_dpdk()
{
    make ./l3-kni.mengbo/l3-kni
    if [ $? -ne 0 ] ; then
            echo "-----------make failed"
            restore_env
            exit
        else
            echo "-----------make success"
    fi
}

check_program_status()
{
    
     #检查DPDK 的app 是否正在运行
     dpdk_pid=$(ps -ef |grep "/app/${APP_NAME}" |grep -v grep | awk '{print $2}')
    if [ -n "$dpdk_pid" ]; 
    then
    echo "dpdk process is running [$dpdk_pid]"
    echo "if you want restart please run stop-dpdk-suricata.sh,then run this"
    exit
    fi

    #检查suricata是否正在运行
    suricata_pid=`ps -ef |grep "/usr/c_app/suricata/suricata*"  |grep -v grep| awk '{print $2}'`
    if [ ! -z "$suricata_pid" ]; 
    then
        echo "suricata process is running [$suricata_pid] "
        echo "if you want restart please run stop-dpdk-suricata.sh,then run this"
        exit    
    fi
} 
#-----------------------------一些函数定义 end -------------------------------------------------------------------



#-----------------------------脚本从这里开始运行 start -------------------------------------------------------------------


#检查是否有dpdk,suricata进程正在运行
check_program_status

echo "start set dpdk   enviroment........................."

#设置大叶内存
HUGEPGSZ=$(cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' ')
set_non_numa_pages

#启用igb_uio模块,并解绑原绑定igb_uio的所有网卡
load_igb_uio_module

#先把所有网卡绑回内核
bind_back_kenel

#从配置文件里读取dpdk使用的物理网卡 
read_pcap_yaml="/usr/c_app/suricata/etc/pcap_test_read.yaml"
physics_net=$( grep -a "interface*" $read_pcap_yaml  | grep -v "#" | cut -d : -f 2 )

if [ -z "$physics_net" ]
then
	echo "/usr/c_app/suricata/etc/pcap.yaml has no interfaces,check it!!!!"
	restore_env
  exit
fi

suppose_kni_nums=0

#检查是否存在这个网卡,存在则将其绑定igb_uio,不存在则退出
for net_name in ${physics_net[@]};do
    ifconfig -a | grep $net_name
    if [ $? -eq 0 ]
    then
         #获取网卡物理队列数,计算suppose_kni_nums
        physics_queue=$( ethtool -l $net_name | grep Combined | head -n 1 | cut -d : -f 2 )
        (( suppose_kni_nums = ${suppose_kni_nums} + ${physics_queue}*${DPDK_CONFIG_QUEUE} ))

        ifconfig $net_name down  #先关闭网卡
         #绑定UIO模块到网卡
         ./usertools/dpdk-devbind.py --bind=igb_uio $net_name
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
   # ./usertools/dpdk-devbind.py --status | grep "if=$net_name drv=igb"
    ifconfig -a | grep $net_name
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


#后台运行dpdk程序
chmod 777 ./app/${DPDK_APP_NAME}
nohup  ./app/${DPDK_APP_NAME} > dpdk.log 2>&1 &

#dpdk没有启动成功，返回非0
if [ $? -ne 0 ] ; then
        echo "-----------dpdk run failed"
		restore_env
        exit
fi


echo "suppose_kni_nums is ${suppose_kni_nums}"

getkni_ex_count=0
while true ; do
    sleep 1
    cur_kni_nums=$(ifconfig -a | grep vEth | cut -d : -f 1 | tr -d ':' |wc -l)
    if [ $cur_kni_nums -eq  $suppose_kni_nums ]; then
        echo "find all kni_net"
        break
    else
        (( getkni_ex_count = ${getkni_ex_count} + 1 ))
        echo now cur_kni_nums is $cur_kni_nums
        echo kni_net is not enough ,continue to wait program to generate kni nets, getkni_ex_count = ${getkni_ex_count}.
    fi
done


#获取所有kni生成的网卡名，并把网卡名写入到suricata配置文件中
kni_net=$(ifconfig -a | grep vEth | cut -d : -f 1 | tr -d ':' )

echo $kni_net

#确保所有虚拟网卡启动起来
for each_net in $kni_net
do
  #启动起来直到成功
    loop_exe "ifconfig $each_net up"
done

pcapYaml="/usr/c_app/suricata/etc/pcap_dpdk.yaml"
# 判断pcap.yaml 是否存在
if [ ! -f "$pcapYaml" ]; then
 touch "$pcapYaml"
fi

#写入pcap.yaml文件
#先清空pcap.yaml文件
echo "" >  $pcapYaml
echo "%YAML 1.1"  >> $pcapYaml
echo "---"  >> $pcapYaml
echo "pcap:" >> $pcapYaml
for line in $kni_net
do 
    echo "- interface: $line" >> $pcapYaml
    echo "- buffer-size: 134217728" >> $pcapYaml
    echo "- threads: auto" >> $pcapYaml
done

#---------------suricata start----------------------------------------------------
#启动新的suricata
echo "start suricata process..."
rm -rf /datadb/suricata/run/suricata.pid
/usr/c_app/suricata/suricata -c /usr/c_app/suricata/etc/suricata.yaml --pidfile /datadb/suricata/run/suricata.pid --pcap -D
#suricata启动报错，返回非0
if [ $? -ne 0 ] ; then
        echo "-------Failed !----something errors when start suricata ,check it !! "
		restore_env
        exit
fi
