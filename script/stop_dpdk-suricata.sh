
HUGEPGSZ=$(cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' ')
HOST_DRIVE=igb

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

bind_back_kenel()
{
        #找到没有被  [内核驱动igb] 和 [igb_uio驱动]   绑定的网卡
        nodrive_net=$( ./usertools/dpdk-devbind.py  -s | grep unused=igb,igb_uio  | awk '{print $1}')
        for  echo_net in $nodrive_net
        do
	        $RTE_SDK/usertools/dpdk-devbind.py -b $HOST_DRIVE  $echo_net #绑回linux内核
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



#------------------------------stop dpdk-suricata -------------------------------

APP_NAME=dpdk-capture
dpdk_pid=$(ps -ef |grep "/app/${APP_NAME}" |grep -v grep | awk '{print $2}')
if [ -n "$dpdk_pid" ]; 
then
   echo "dpdk process is running [$dpdk_pid]"
   echo ""
   kill -9 $dpdk_pid
   echo "stop dpdk-suricata success!!"
   restore_env
else
   echo "there are no dpdk progarm is running.............................."
fi

#检查suricata是否正在运行
suricata_pid=`ps -ef |grep "/usr/c_app/suricata/suricata*"  |grep -v grep| awk '{print $2}'`
if [ ! -z "$suricata_pid" ]; 
then
   echo "suricata process is running [$suricata_pid],now stop it "
   suricatasc /datadb/suricata/run/suricata-command.socket -c shutdown
   sleep 3
   echo "stop suricata success!!"
else
    echo "there are no suricata progarm is running.............................."
fi
 
