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
#include <rte_ether.h>
#include <rte_ethdev.h>

#include "decode.h"

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MEMPOOL_CACHE_SIZE 256

#define	RTE_MBUF_DEFAULT_DATAROOM	2048
#define	RTE_MBUF_DEFAULT_BUF_SIZE	\
	(RTE_MBUF_DEFAULT_DATAROOM + RTE_PKTMBUF_HEADROOM)

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

/* Number of mbufs in mempool that is created */
#define NB_MBUF       (8192 * 16)

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static int m_b_load_pcap_file = 1;


static struct rte_mempool *mbuf_pools[RTE_MAX_ETHPORTS];
/* Mempool for mbufs */
static struct rte_mempool * pktmbuf_pool = NULL;


/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,	/* 使用 RSS 分流 */
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.offloads = DEV_RX_OFFLOAD_CHECKSUM,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,/* 留给 网卡设置 rss_key */  // (uint8_t*)rss_intel_key;
			.rss_hf = ETH_RSS_IP,/* 根据 l3 tuple 计算 rss hash */
		},
	},// 为设备使能RSS
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};



int LoadPcapFile()
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
            struct pcap_packet *p = (struct pcap_packet *)malloc(sizeof(struct pcap_packet*));
            if(p)
            {
                p->len = h->caplen;
                p->next = NULL;
                p->pkt = (char*)malloc(p->len);
                if(p->pkt != NULL)
                {
                    memcpy(p->pkt,pkt,p->len);
                }
                else
                {
                   printf("Not enough memory\n");
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
               printf("Not enough memory\n");
               break;
            }
            num_pcap_pkts++;
            bytes_pcap += p->len;
        }
        pcap_close(pt);
        printf("Read %d packets from pcap file %s\n",num_pcap_pkts,m_pcap_file.c_str());
        last->next = pkt_head;
    }
    else
    {
       printf("Unable to open file %s\n",m_pcap_file.c_str());
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


void dpdk_init()
{
    uint32_t _core_id = 0;
    unsigned long coreMask= 0;
    coreMask |= 1<<_core_id;
    char coreMaskBuf[64]{0};
    snprintf(coreMaskBuf,sizeof(coreMaskBuf),"0x%1x",coreMask);
    int argc = 3;
    //dpdk EAL的参数
    char *argv[] = {"./udprobe",//运行程序
                        "-c",
                        coreMask};

    int ret = rte_eal_init(argc,argv);
    if( ret <0 )
        rte_exit(EXIT_FAILURE,"Error with EAL initialization\n");
    argc -= ret;
	argv += ret;


    //创建mbuf_pools池
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
	if (pktmbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
		return -1;
	}

   /* Initialise each port */
	RTE_ETH_FOREACH_DEV(port) {
        //端口初始化
        if(port_init(portid,mbuf_pools[portid]) != 0)
            rte_exit(EXIT_FAILURE,"Cannot init port %d \n",portid);
    }


    //检查链路状态
  //  check_all_ports_link_status(ports_mask);

 //   std::thread dpdk_stat_thread(DpdkStatThreadRun);
  //  dpdk_stat_thread.detach();

}

//dpdk端口初始化
static int port_init(uint8_t port,struct rte_mempool *mbuf_pool)
{
    const uint16_t rx_rings = prehand_threads[port+1],tx_rings = 1;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf local_port_conf = port_conf;
    int retval;
    static struct rte_eth_rxconf  rxq_conf;
    struct rte_eth_txconf txq_conf;
  
    if(port >= rte_eth_dev_count())
        return -1;

    //配置dpdk网口的接收队列数和发送队列数
	ret = rte_eth_dev_configure(port, 1, 1, &local_port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not configure port%u (%d)\n",
		            (unsigned)port, ret);

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port,&nb_rxd,&nb_txd);
    if(retval != 0)
        return retval;

    ret = rte_eth_dev_info_get(port, &dev_info);
	printf("端口：%d默认的最大接收队列数：%d\n",port,dev_info.max_rx_queues);

    rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;

    for(uint16_t q = 0;q<rx_rings;q++)
    {
        //对每一个端口，分配和建立一个相应的接收队列
        retval = rte_eth_rx_queue_setup(port,0,nb_rxd,rte_eth_dev_socket_id(port),&rxq_conf,mbuf_pool);
        if(rteval <0 )
        {
            rte_exit(EXIT_FAILURE,"rte_eth_rx_queue_setup: err=%d, port=%d\n",ret, portid);
            return retval;
        }
    }

    txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
    for(uint16_t q = 0;q<tx_rings;q++)
    {
         //对每一个端口，分配和建立一个相应的接收队列
        retval = rte_eth_tx_queue_setup(port,0,nb_txd,rte_eth_dev_socket_id(port),&txq_conf);
        if(retval <0 )
        {
            rte_exit(EXIT_FAILURE,"rte_eth_rx_queue_setup: err=%d, port=%d\n",ret, portid);
            return retval;
        }
    }

    //端口开启混杂模式
    ret = rte_eth_promiscuous_enable(port);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,"Could not enable promiscuous mode for port%u: %s\n",
				port, rte_strerror(-ret));

    //开启端口
    retval = rte_eth_dev_start(port);
    if(retval < 0)
    {
        printf("start  dpdk dev failed!!\n");
        return retval;
    }
    
    return 0;
}


void DpdkRun(uint16_t queue_id)
{
    //分配CPU核
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
        //LOG_MSG(LOG_LEVEL_ERROR,"capture queue is null,queue id:%u",queue_id);
        printf("capture queue is null,queue id:%u",queue_id);
        exit(-1);
    }

    while(rCaptureThreadStartFlag)
    {
       
        //接收网卡流量数据
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
        //从环里入队
        int ret = capture_ring->EnqueueBurst((void* const*)mbufs,nb_rx,NULL);
        if(nb_rx != ret)
        {
            droped_packets += nb_rx - ret;
            LOG3_MSG(5000000,LOG_LEVEL_ERROR,"[Watchout] prehand queue is full,total droped packets: %d",droped_packets);
            for(int i=0;i<nb_rx;i++)
                rte_pktmbuf_free(mbufs[i]);
        }
    }
}

void prehandle_loop()
{
     CaptureThreadStartFlag[m_cap_port] = true;
     auto &rCaptureThreadStartFlag = CaptureThreadStartFlag[m_cap_port];
     struct rte_mbuf *mbufs[MBUF_NUMS];
     uint32_t burst_size = 0;
     bool bAllocateCPUSucc = allocate_cpu_core(__FUNCTION__,DESC_MODE);
     while(likely(rCaptureThreadStartFlag))
     {
         // 从环里出队
         burst_size = m_pre_queue->DequeueBurst((void**)mbufs,MBUF_NUMS,NULL);
         if(unlikely(0 == burst_size))
         {
             continue;
         }
         if(likely(burst_size))
         {
             for(int i=0;i<burst_size;i++)
             {
                 //处理包
                 do_handle_packet(mbufs[i]);
                 rte_pktmbuf_free(mbufs[i]);
             }
         }
     }
}

void do_handle_packet(struct rte_mbuf *mbuf)
{
    #if 1
    headinfo h_info = {0};
    tuple4 tuple;
    libpacpfile::pcap_pkthdr pack_hdr;
    //解码头部
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
    uint32_t hash_rss = (mbuf->hash.rss)%m_decode_thread_num;//把包分配到相应的队列
    #else
    uint32_t hash_rss = (find_hash(&h_info))%m_decode_thread_num;
    #endif
    //启用了负载均衡，把网卡流量分往多个队列
    if(unlikely(start_filter_queue_flag))
    {
        std::string packet_s;
        packet_s.assign((char*)&h_info.h_tuple4,PACKET_TUOLE4_LEN);
        packet_s.append(packet,PCAP_HEAD_LEN+pack_hdr.caplen);
        if(!gFilterRingQueue->push(std::move(packet_s)))
        {
            LOG3_MSG(5000000,LOG_LEVEL_WARN,"[Watchout] gFilterRingQueue size:%d is full!!",gFilterRingQueue->get_status());
        }
        PushTotal++;
        //入队
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

void loop()
{
    _running = true;
    unsigned long mask = 1 << _probe_if;
    CaptureThreadStartFlag[_probe_if] = true;
    bool bAllocateCPUSucc = allocate_cpu_core(__FUNCTION__,ASC_MODE);
   // bool insert_key = kafa_sync_thread.insert({std::this_thread::get_id(),false});
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



int main()
{

    uint16_t nb_ports;
    nb_ports = rte_eth_dev_count_avail();//获取当前有效网口的个数
    if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    //dpdk环境初始化
    dpdk_init();

    //若从pcap文件读取流量，则交给PcapRun处理
    if(m_b_load_pcap_file)
    {
        //pcap初始化
        PcapRunInit();
        if(LoadPcapFile() >= 0)
        {
            prehandle_loop();
           // m_thread.reset(new boost::thread(boost::bind(PcapRun,this)));
        }   
    }else //若从网卡直接读取流量，则交给DpdkRun处理
    {

        DpdkRun();

        //每个端口对应一个线程来处理
        /*
        for(int i=0;i<prehand_threads[nb_ports];i++)
        {
            std::thread dpdk_run_thread(boost::bind(DpdkRun,this,i));
            dpdk_run_thrad.detach();
        }*/
    
    }
}

