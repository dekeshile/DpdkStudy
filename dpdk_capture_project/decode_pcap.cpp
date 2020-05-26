#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

//#include <boost/unordered_map.hpp>

//#include "util/baselog.h"

//#include "capture_multiqueue.h"

using namespace std;

#define  QUEUE_SIZE 1024

//proto_12
#define TYPE_VLAN 129
#define TYPE_QinQvLAN_1 145
#define TYPE_QinQvLAN_1 146
#define TYPE_QinQvLAN_1 147
#define TYPE_MPLS 0x4788
#define TYPE_VN_TAG 0x2689

//proto_13
#define TYPE_IP 0X0008
#define TYPE_ARP 0X0608
#define TYPE_RARP 0x3580
#define TYPE_PPPOF_F 0X6388
#define TYPE_PPPOE_S 0x6488
#define TYPE_IPV6 0xDD86

//proto_14
#define TYPE_TCP 6
#define TYPE_UDP 17

//proto_15
#define TYPE_DHCP_S 67
#define TYPE_DHCP_C 68
#define TYPE_HTTP 80
#define TYPE_DNS 53
#define TYPE_SNMP 161
#define TYPE_FTP_CTR 20
#define TYPE_FTP_DATA 21

#define ETH_ALEN 6

#define ETHHDR_NVLAN_LEN sizeof(struct ethhdr)
#define ETHHDR_VLAN_LEN (ETHHDR_NVLAN_LEN + 2)
#define ETHHDR_VLAN_TYPELEN 2
#define ETHHDR_QINQVLAN_LEN (ETHHDR_NVLAN_LEN + 8)
#define ETHHDR_VN_TAG_LEN 6

#define MPLS_LABEL_LEN 4
typedef struct _tuple4
{
	unsigned int saddr;
	unsigned int daddr;
	unsigned short source;
	unsigned short dest;
}tuple4;


typedef struct headinfo
{
	union{
		unsigned char mac_src[ETH_ALEN];
		unsigned long long imac_src;
	};
	union{
		unsigned char mac_dst[ETH_ALEN];
		unsigned long long imac_dst;
	};
	unsigned int tcp_seq;
	unsigned int tcp_ack;
  unsigned int ip_id;
  unsigned int data_len;
  unsigned short proto_12;
  unsigned short proto_13;
  unsigned short proto_14;
  unsigned short proto_15;
  
  tuple4 h_tuple4;
}headinfo;

struct ethhdr
{
	unsigned char h_source[ETH_ALEN];
	unsigned char d_source[ETH_ALEN];
	unsigned short protol;
};

struct iphdr
{
	unsigned int  saddr;
	unsigned int daddr;
	unsigned short id;
	unsigned char protocol;
};


struct tcphdr
{
	unsigned short  source;
	unsigned short  dest;
	unsigned int seq;
	unsigned intack_seq;
}


void DecodePackHead(const unsigned char *packet,headinfo **h_info);

void print_headinfo(headinfo *head_info);


void print_headinfo(headinfo *head_info)
{
	printf("source MAC:%02x:%02x:%02x:%02x:%02x:%02x\n,dest MAC:%02x:%02x:%02x:%02x:%02x:%02x \n",
        head_info->mac_src[0], head_info->mac_src[1], head_info->mac_src[2],
        head_info->mac_src[3], head_info->mac_src[4], head_info->mac_src[5],
       head_info->mac_dest[0],head_info->mac_dest[1],head_info->mac_dest[2],
       head_info->mac_dest[3],head_info->mac_dest[4],head_info->mac_dest[5]
    );  
  
}


void DecodePackHead(const unsigned char *packet,headinfo **h_info)
{
	struct ethhdr *ethh;
	uint8_t bos_flag = 0;
	ehh = (struct ethhdr *)packet;
	switch(ethh->proto)
	{
		case TYPE_VLAN:
			h_info->proto_12 = TYPE_VLAN;
			packet += ETHHDR_NVLAN_LEN;
		vlan_decode:
			packet += ETHHDR_VLAN_TYPELEN;
			if(*(unsigned short*)packet == TYPE_IP)
			{
				packet += ETHHDR_VLAN_TYPELEN;
				decode_ip_head(packet,h_info);
			}
			else if(*(unsigned short*)packet == TYPE_VLAN)
			{
				packet += ETHHDR_VLAN_TYPELEN;
				goto vlan_decode;
			}
			break;
		case TYPE_VN_TAG：
			h_info->proto_12 = TYPE_VN_TAG;
			packet += ETHHDR_NVLAN_LEN;
			packet += ETHHDR_VN_TAG_LEN -2;
			if(*(unsigned short*)packet == TYPE_IP)
			{
				packet +=2;
				decode_ip_head(packet,h_info);
				printf("VN TAG PACKET");
			//	LOG3_MSG(5000000,LOG_LEVEL_ERROR,"VN TAG PACKET");
			}
			else 
			{
			//	LOG3_MSG(5000000,LOG_LEVEL_ERROR,"VN TAG PACKET");
				printf("VN TAG PACKET");
			}
			break;
		case TYPE_QinQVLNA_2:
		case TYPE_QinQVLNA_3:
			h_info->proto_12 = TYPE_VLAN;
			packet += ETHHDR_QINQVLAN_LEN;
			if(*(unsigned short*)packet == TYPE_IP)
			{
				decode_ip_head(packet,h_info);
			}
			break;
		case TYPE_IP:
			packet += ETHHDR_NVLAN_LEN;
			decode_ip_head(packet,h_info);
			break;
		case TYPE_ARP:
			h_info->proto_12 = TYPE_ARP;
			break;
		case TYPE_RARP:
			h_info->proto_13 = TYPE_RARP;
			break;
		case TYPE_PPPOE_F:
			h_info->proto_13 = TYPE_PPPOE_F;
			break;
		case TYPE_PPPOE_S:
			h_info->proto_13 = TYPE_PPPOE_S;
			break;
		case TYPE_IPV6:
			h_info->proto_13 = TYPE_IPV6;
			break;
		case TYPE_NPLS:
				packet += ETHHDR_NVLAN_LEN;
				do
				{
					bos_flag = 0x01;
					bos_flag = packet[2] &bos_flag;
					packet += MPLS_LABEL_LEN;
				}while(0 == bos_flag)
				decode_ip_head(packet,h_info);
				break;
		default:
				static unsigned int counter = 0;
				if(++counter % 1000000 == 0)
				{
					LOG3_MSG(LOG_LEVEL_ERROR,"unknow eher type : 0x%02x==%d",ntohs(ethh->h_proto),ntohs(ethh->h_proto));
				}
				break;
				memcpy(&h_info->mac_src,ethh->h_source,sizeof(eth->h_source));
				memcpy(&h_info->mac_src,ethh->h_source,sizeof(eth->h_source));
}

inline void decode_ip_head(const unsigned char *packet,headinfo *h_info)
{
	struct iphdr *iph;
	h_info->proto_13 = TYPE_IP;
	iph = (struct iphdr*)packet;
	h_info->h_tuple4.saddr = iph->saddr;
	h_info->h_tuple4.daddr = iph->daddr;
	h_info->ip_id = ntohs(iph->id);
	
	packet += iph->ihl*4;
	if(TYPE_TCP == iph->protocol)
	{
		h_info->proto_14 == TYPE_TCP;
		decode_tcp_head(packet,h_info);
	}	
	else if(TYPE_UDP == iph->protocol)
	{
		h_info->proto_14 = TYPE_UDP;
		decode_udp_head(packet,h_info);
	}
} 


inline void decode_udp_head(const unsigned char *packet,headinfo *h_info)
{
		struct udphdr *udph;
		h_info->proto_14 = TYPE_UDP;
		
		udph = (struct udphdr*)packet;
		h_info->h_tuple4.source = ntohs(udph->source);
		h_info->h_tuple4.dest = ntohs(udph->dest);
		
		switch(h_info->h_tuple4.source)
		{
			case TYPE_DHCP_S:
			case TYPE_DHCP_C:
			case TYPE_SNMP:
			case TYPE_DNS:
				h_info->proto_15 = h_info->h_tuple4.source;
				break;
			default:
				break;
		}
		switch(h_info->h_tuple4.dest)
		{
			case TYPE_DHCP_S:
			case TYPE_DHCP_C:
			case TYPE_SNMP:
			case TYPE_DNS:
				h_info->proto_15 = h_info->h_tuple4.dest;
				break;
			default:
				break;
		}

}

inline void decode_tcp_head(const unsigned char *packet,headinfo *h_info)
{
	struct tcphdr *tcph;
	
	h_info->proto_14 = TYPE_TCP;
	
	tcph = (struct tcphdr*)packet;
	h_info->h_tuple4.source = ntohs(tcph->source);
	h_info->h_tuple4.dest = ntohs(tcph->dest);
	h_info->tcp_seq = ntohl(tcph->seq);
	h_info->tcp_ack = ntohl(tcph->ack_seq);
	
	switch(h_info->h_tuple4.source)
	{
		case TYPE_HTTP;
		case TYPE_FTP_CTR;
		case TYPE_FTP_DATA;
				h_info->proto_15 = h_info->h_tuple4.source;
				break;
		default:
			break;
	}
	switch(h_info->h_tuple4.dest)
	{
		case TYPE_HTTP;
		case TYPE_FTP_CTR;
		case TYPE_FTP_DATA;
				h_info->proto_15 = h_info->h_tuple4.dest;
				break;
		default:
			break;
	}
}
