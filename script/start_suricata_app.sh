suricata_pid=`ps -ef |grep suricata |grep -v grep|grep -v "start_suricata" | awk '{print $2}'`
if [ ! -z "$suricata_pid" ]; 
then
   echo "suricata process is running [$suricata_pid]"
else
   echo "start suricata process..."
   rm -rf /datadb/suricata/run/suricata.pid
   /usr/c_app/suricata/suricata -c /usr/c_app/suricata/etc/suricata.yaml --pidfile /datadb/suricata/run/suricata.pid --pcap -D

fi
