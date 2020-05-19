#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>


struct CCaputrePack
{
    int  LoadPcapFile();
    void DpdkRun(uint16_t queue_id);
    bool Initialize();

};

struct PacketPrehandle
{
    void do_handle_packet(struct rte_mbuf *mbuf);
    void loop();
    void prehandle_loop();
};

int CCaputrePack::LoadPcapFile()
{
    if(send_len < 60)
        send_len = 60;
    if(gbit_s >0 )
    {
        hz = rte_get_timer_hz();
        printf("Estimated CPU freq: %llu  Hz \n",hz);
        printf("Number of %d-byte Packet Per Second at %.2f Gbit/s\n",(send_len + 4),gbit_s);
    }
    char ebuf[256];
    pcap_t *pt = pcap_open_offline(m_pcap_file.c_str(),ebuf);
    u_int num_pcap_pkts = 0;
    uint64_t bytes_pcap = 0;

    if(pt)
    {
        u_char * pkt;
        struct pcap_pkthdr *h;
        struct pcap_packet *last = NULL;
        while(1)
        {
            int rc = pcap_next_ex(pt,&h,(const u_char **)&pkt);
            if(rc <= 0)
                break;
            struct pcap_packet *p = (struct pcap_packet *)malloc(sizeof(struct pcap_packet));
            if(p)
            {
                p->len = h->caplen;
                p->next = NULL;
                p->pkt = (char*)malloc(p->len);
                if(p->pkt != NULL)
                {
                    memcpy(p->pkt,pkt,p->len);
                    #if 0
                    string tep((char*)pkt,p->len);
                    if(tep.find("POST /yd-bpm-web/login/dologin.action") != std::string::npos)
                    {
                        static unsigned long c = 0;
                        LOG_MSG(LOG_LEVEL_ERROR,"=======%u:%s",++c,tep.c_str());
                    }
                    #endif
                }
                else
                {
                   LOG_MSG(LOG_LEVEL_ERROR,"Not enough memory");
                   break;
                }
                headinfo h_info;
                DecodePackHead((uint8_t*)p->pkt,&h->info);
                p->hash_key = find_hash(&h_info);
                if(last)
                {
                    last->next = p;
                    last = p;
                }
                else
                {
                   pkt_head = p,last = p;
                } 
            }
            else
            {
               LOG_MSG(LOG_LEVEL_ERROR,"Not enough memrory");
               break;
            }
            num_pcap_pkts++;
            bytes_pcap += p->len;
        }
        pcap_close(pt);
        LOG_MSG(LOG_LEVEL_NOTICE,"Read %d packets from pcap file %s",num_pcap_pkts,m_pcap_file.c_str());
        last->next = pkt_head;
    }
    else
    {
        LOG_MSG(LOG_LEVEL_ERROR,"Unable to open file %s",m_pcap_file.c_str());
        return(-1);
    }
    uint64_t packet_avg_size = bytes_pcap/num_pcap_pkts;
    uint64_t pps =((1000*1000000ULL)/packet_avg_size)*gbit_s)/100;
    uint64_t cpp = hz/pps;
    ts_cycles = cpp;

    gettimeofday(&startTime,NULL);
    memcpy(&lastTime,&startTime,sizeof(startTime));
    tosend = pkt_head;
    return(0);
}

void dpdk_init_main()
{
    uint32_t _core_id = 0;
    unsigned long coreMask= 0;
    coreMask |= 1<<_core_id;
    char coreMaskBuf[64]{0};
    snprintf(coreMaskBuf,sizeof(coreMaskBuf),"0x%1x",coreMask);
    int argc = 3;
    char *argv[] = {"./udprobe","-c",coreMask};

    int ret = rte_eal_init(argc,argv);
    if( ret <0 )
        rte_exit(EXIT_FAILURE,"Error with EAL initialization\n");
}

bool CCaputrePack::Initialize()
{
    if(m_b_load_pcap_file)
    {
        dpdk_init(m_nInterfaceId-1);
        PcapRunInit();
        if(LoadPcapFile() >= 0)
        {
            m_thread.reset(new boost::thread(boost::bind(&CCaputrePack::PcapRun,this)));
        }
        else
        {
            dpdk_init(m_nInterfaceId-1);
            for(int i=0;i<prehand_threads[m_nInterfaceId];i++)
            {
                std::thread dpdk_run_thread(boost::bind(&CCaputurePack::DpdkRun,this,i));
                dpdk_run_thrad.detach();
            }
        }
        
    }
}

void dpdk_init(uint8_t portid)
{
    unsigned nb_ports;//网口个数
    nb_ports = rte_eth_dev_count();//获取当前有效网口的个数
    char mbuf_pool_name[128]{0};
    //for(int i=0;i<nb_ports;i++)
    {
        snprintf(mbuf_pool_name,128,"MBUF_POOL_%d",portid);
        mbuf_pools[portid] = rte_pktmbuf_pool_create(mbuf_pool_name,gkafkasync,capture_mbuf_pool_size,
        MBUF_CACHE_SIZE,0,RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());
        if(mbuf_pools[portid] == NULL)
            rte_exit(EXIT_FAILURE,"Cannot create mbuf pool\n");
    }

  //  for(portid = 0;portid < nb_ports;portid++)
        if(port_init(portid,mbuf_pools[portid]) != 0)
            rte_exit(EXIT_FAILURE,"Cannot init port %d \n",portid);
    std::thread dpdk_stat_thread(DpdkStatThreadRun);
    dpdk_stat_thread.detach();
}

static int port_init(uint8_t port,struct rte_mempool *mbuf_pool)
{
    const uint16_t rx_rings = prehand_threads[port+1],tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    static struct rte_eth_conf port_conf;
    port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t*)rss_intel_key;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP|ETH_RSS_PORT;

    if(gkafkasync.jumbo_frame)
    {
        port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN*10;
        port_conf.rxmode.jumbo_frame = 0;
    }
    else
    {
        port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
        port_conf.rxmode.jumbo_frame = 0;
    }
    if(port >= rte_eth_dev_count())
        return -1;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port,&nb_rxd,&nb_txd);
    if(retval != 0)
        return retval;
    if(port_conf.rxmode.jumbo_frame)
    {
        if(rte_eth_dev_set_mtu(port,port_conf.rxmode.max_rx_pkt_len)!=0)
            LOG_MSG(LOG_LEVEL_ERROR,"port %d Set MTU=[%d] failed.",port,port_conf.rxmode.max_rx_pkt_len);
        static struct rte_eth_rxconf   rxconf;
        rxconf.rx_free_thresh = 32;
        for(uint16_t q = 0;q<rx_rings;q++)
        {
            retval = rte_eth_rx_queue_setup(port,q,nb_rxd,
            rte_eth_dev_socket_id(port),&rxconf,mbuf_pool);
            if(rteval <0 )
            {
                return retval;
            }
            for(uint116_t q = 0;q<tx_rings;q++)
            {
                retval = rte_eth_tx_queue_setup(port,q,nb_txd,
                rte_eth_dev_socket_id(port),NULL);
                if(retval <0 )
                {
                    return retval;
                }
            }
            retval = rte_eth_dev_start(port);
            if(retval < 0)
            {
                LOG_MSG(LOG_LEVEL_ERROR,"start  dpdk dev failed!!");
                return retval;
            }
            rte_eth_promiscuous_enable(port);
      
        } 
    }
#if 0 
    retval = rte_eth_dev_start(port);
    if(retval < 0)
        return retval;
    struct ether_addr addr;
    rte_eth_macaddr_get(port,&addr);
    printf("Port %u MAC: %02x %02x %02x %02x %02x %02x\n",
        (unsigned)port,
        addr.addr_bytes[0],addr.addr_bytes[1],
        addr.addr_bytes[2],addr.addr_bytes[3],
        addr.addr_bytes[4],addr.addr_bytes[5]
    );
#endif
    return 0;
}

void dpdk_stat(unsigned portid)
{
    struct rte_eth_stats eth_stats;
    rte_eth_stats_get(portid-1,&eth_stats);
    if(capcounters[portid].flag == 0)
    {
        capcounters[portid].prev_droped_packets = eth_stats.imissed;
        capcounters[portid].prev_error_packets= eth_stats.rx_nombuf;
        capcounters[portid].prev_grain_bytes = eth_stats.ibytes;
        capcounters[portid].prev_grain_packets = eth_stats.ipackets;
        capcounters[portid].flag = 1;
    }
    else
    {
        unsigned long device_droped = eth_stats.imissed - capcounters[portid].prev_droped_packets;
        unsigned long device_errord = eth_stats.rx_nombuf - capcounters[portid].prev_error_packets;
        unsigned long cur_grain_traffic = eth_stats.ibytes - capcounters[portid].prev_grain_bytes;
        unsigned long cur_grain_packets = eth_stats.ipackets -  capcounters[portid].prev_grain_packets;
        unsigned long avgpkts = cur_grain_packets >> 4;
        unsigned long avgbyte = cur_grain_traffic >> 4;
        double avggbps = (double)avgbyte / ((1000*1000*1000) >> 3);
        LOG_MSG(device_droped > 0 ? LOG_LEVEL_ERROR : LOG_LEVEL_INFO,
        "[Watchout][Capture][iface:%d][queue:%d][speed:%.31fGbps][packet:%lupkt/s]"
        "[cur_grain_traffic:%lu][lost:0%%][pkts_in:%lu][mbuf_error:%lu][droped:%lu]",
        portid,
        g_queue_num[portid],
        avggbps,
        avgpkts,
        cur_grain_traffic,
        eth_stats.ipackets,device_errord,device_droped
        );
        capcounters[portid].prev_droped_packets = eth_stats.imissed;
        capcounters[portid].prev_error_packets= eth_stats.rx_nombuf;
        capcounters[portid].prev_grain_bytes = eth_stats.ibytes;
        capcounters[portid].prev_grain_packets = eth_stats.ipackets;
    }
    
}

void CCaputrePack::DpdkRun(uint16_t queue_id)
{
    bool bAllocateCPUSucc = allocate_cpu_core(_FUNCTION_,ASC_MODE);
    struct timeval ts;
    is_running = true;
    int nb_rx = 0;
    unsigned long long cur_total_bytes = 0;
    struct rte_mbuf *mbufs[BURST_SIZE];
    const int prehand_nums = m_Cap2PreMapQueue->size();
    CaptureThreadStartFlag[m_nInterfaceId] = true;
    auto &rCaptureThreadStartFlag = CaptureThreadStartFlag[m_nInterfaceId];
    CapturePackQueue *capture_ring = NULL;
    if(m_Cap2PreMapQueue->at(queue_id) != NULL)
    {
        capture_ring = m_Cap2PreMapQueue->at(queue_id);
    }
    else
    {
        LOG_MSG(LOG_LEVEL_ERROR,"capture queue is null,queue id:%u",queue_id);
        exit(-1);
    }
    struct ether_addr addr;
    rte_eth_macaddr_get(dpdk_port_id,&addr);
    printf("Port %u MAC: %02x  %02x  %02x  %02x  %02x  %02x\n",
         (unsigned)dpdk_port_id,
         addr_addr_bytes[0],addr.addr_bytes[1],
         addr_addr_bytes[2],addr.addr_bytes[3],
         addr_addr_bytes[4],addr.addr_bytes[5]
         );
    while(rCaptureThreadStartFlag)
    {
        if(0 == g_enable_diable_probe_flag)
        {
            sleep(1);
            LOG_MSG(LOG_LEVEL_NOTICE,"upprobe be in inactive state!");
            continue;   
        }
        nb_rx = rte_eth_rx_burst(dpdk_port_id,queue_id,mbufs,BURST_SIZE);
        if(nb_rx <= 0)
        {
            gettimeofday(&ts,0);
        }
        for(int i=0;i<nb_rx;i++)
        {
            gettimeofday(&ts,0);
            mbufs[i]->udata64 = ((uint64)ts.tv_sec << 32) | (uint64_t)ts_usec;
        }
        int ret = capture_ring->EnquueBurst((void* const*)mbufs,nb_rx,NULL);
        if(nb_rx != ret)
        {
            droped_packets += nb_rx - ret;
            LOG3_MSG(5000000,LOG_LEVEL_ERROR,"[Watchout] prehand queue is full,total droped packets: %d",droped_packets);
            for(int i=0;i<nb_rx;i++)
                rte_pktmbuf_free(mbufs[i]);
        }
    }
}

void PacketPrehandle::prehandle_loop()
{
     CaptureThreadStartFlag[m_cap_port] = true;
     auto &rCaptureThreadStartFlag = CaptureThreadStartFlag[m_cap_port];
     struct rte_mbuf *mbufs[MBUF_NUMS];
     uint32_t burst_size = 0;
     bool bAllocateCPUSucc = allocate_cpu_core(__FUNCTION__,DESC_MODE);
     while(likely(rCaptureThreadStartFlag))
     {
         burst_size = m_pre_queue->DequeueBurst((void**)mbufs,MBUF_NUMS,NULL);
         if(unlikely(0 == burst_size))
         {
             continue;
         }
         if(likely(burst_size))
         {
             for(int i=0;i<burst_size;i++)
             {
                 do_handle_packet(mbufs[i]);
                 rte_pktmbuf_free(mbufs[i]);
             }
         }
     }
}

void PacketPrehandle::do_handle_packet(struct rte_mbuf *mbuf)
{
    #if 1
    headinfo h_info = {0};
    tuple4 tuple;
    libpacpfile::pcap_pkthdr pack_hdr;
    DecodePackHead(rte pktmbuf mtod(mbuf,const unsigned char *),&h_info);
    pack_hdr.caplen = pack_hdr.len = rte_pktmbuf_pkt_len(mbuf);
    pack_hdr.ts.tv_sec = mbuf->udata64 >> 32;
    pack_hdr.ts.tv_usec = mbuf->udata64 & 0xFFFFFFFF;
    ++total;
    if(!is_match_filter(m_cap_port,&h_info))
    {
        ++count;
        LOG3_MSG(5000000,LOG_LEVEL_NOTICE,"IP IS src:%s,dst:%s,prehandle_map_size:%d,filer:%llu,total:%llu,[%lf-%lf-%2.3lf]",
        InetNtoa((h_info.h_tuple4.saddr)).c_str(),
        InetNtoa((h_info.h_tuple4.daddr)).c_str(),prehandle_fileter_map[m_cap_port].size(),
        count,total,PushTotal,PushDrop,PushDrop/PushTotal);
        return;
    }
    #endif

    char* packet = (char*)tc_malloc(PCAP_HEAD_LEN+pack_hdr.caplen);
    rte_memcpy(packet,&pack_hdr,PCAP_HEAD_LEN);
    auto m = mbuf;
    int curlen  = 0;
    while(m)
    {
        rte_memcpy(packet+PCAP_HEAD_LEN+curlen,rte_pktmbuf_mtod(m,char*),rte_pktmbuf_data_len(m));
        curlen += rte_pktmbuf_data_len(m);
        m = m->next;
    }
    #if 1
    uint32_t hash_rss = (mbuf->hash.rss)%m_decode_thread_num;
    #else
    uint32_t hash_rss = (find_hash(&h_info))%m_decode_thread_num;
    #endif
    if(unlikely(start_filter_queue_flag))
    {
        std::string packet_s;
        packet_s.assign((char*)&h_info.h_tuple4,PACKET_TUOLE4_LEN);
        packet_s.append(packet,PCAP_HEAD_LEN+pack_hdr.caplen);
        if(!gFilterRingQueue->push(std::move(packet_s)))
        {
            LOG3_MSG(5000000,LOG_LEVEL_WARN,"[Watchout] gFilterRingQueue size:%d is full!!",gFilterRingQueue->get_status());
        }
        #if 1
        if(gkafkasync.data_storage_swithc)
        {
            if(!g_StorePacket[m_cap_port][m_pre_queue->GetPreIndex()]->PushPacket((const unsigned char*)packet+PCAP_HEAD_LEN,&pack_hdr,&h_info))
                LOG3_MSG(5000000,LOG_LEVEL_ERROR,"[Watchout] PORT:[%d:%d] STORE QUEUE IS FULL",m_cap_port,m_pre_queue->GetPreIndex());
        }
        #endif
        PushTotal++;
        if(!(*m_decode_queue)[hash_rss]->Enqueue((void*)packet))
        {
             LOG3_MSG(10*1000*1000,LOG_LEVEL_NOTICE,
             "[Watchout][PreHandle][capture_iface:%d][queue:%d][decode_queue:%d][size:%d][capacity:%d]",
             m_cap_port,g_queue_num[m_cap_port],
             (*m_decode_queue)[hash_rss]->GetPreIndex(),
             (*m_decode_queue)[hash_rss]->UsedSize(),
             (*m_decode_queue)[hash_rss]->Captity(),
        }
        else
        {
            PushDrop++;
            tc_free(packet);
            LOG3_MSG(10*1000*1000,LOG_LEVEL_NOTICE,
             "[Watchout][PreHandle][capture_iface:%d][queue:%d][decode_queue:%d][size:%d][capacity:%d]",
             m_cap_port,g_queue_num[m_cap_port],
             (*m_decode_queue)[hash_rss]->GetPreIndex(),
             (*m_decode_queue)[hash_rss]->UsedSize(),
             (*m_decode_queue)[hash_rss]->Captity(),
        }
    }
}

void PacketPrehandle::loop()
{
    _running = true;
    unsigned long mask = 1 << _probe_if;
    CaptureThreadStartFlag[_probe_if] = true;
    bool bAllocateCPUSucc = allocate_cpu_core(__FUNCTION__,ASC_MODE);
    bool insert_key = kafa_sync_thread.insert({std::this_thread::get_id(),false});
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    std::string stid = oss.str();
    _tid = std::stoull(stid);
    HsMapAsynStateTbbMap.insert(std::pair<uint64_t,unsigned>(_tid,0));
    auto &rCaptureThreadStartFlag = rCaptureThreadStartFlag[_probe_if];
    char* packets[MBUF_NUMS];
    unsigned int burst_size = 0;
    struct timeval ts;
    while(likely(rCaptureThreadStartFlag))
    {
        burst_size = _pktc->DequeueBurst((void**)packets,MBUF_NUMS,NULL);
        if(unlikely(0 == burst_size))
        {
            gettimeofday(&ts,0);
            _cur_tag = ts.tv_sec;
            if(!_end_tag)
            {
                SetTimeFlag();
            }
            if(_end_tag < _cur_tag)
            {
                LOG3_MSG_THREAD(1000000,LOG_LEVEL_NOTICE,"no packet need decode");
                tcp_reassemble()->TcpCheckTcpStreamQueue(_cur_tag);
                SetTimeFlag();
            }
            usleep(10);
            continue;
        }
        for(int i=0;i<burst_size;i++)
        {
            DecodeOnePack(packets[i]);
            tc_free(packets[i]);
        }
        LOG3_MSG_THREAD(10*1000*1000,LOG_LEVEL_NOTICE,
             "[Watchout][Decode][decode_queue:%s][size:%d][capacity:%d]",
             _pktc->GetQueueIndex().c_str(),_pktc->UsedSize(),_pktc->Captity());
    }
}