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


void DecodePackHead(const unsigned char *packet,headinfo *h_info);

void print_headinfo(headinfo *head_info);

inline void decode_ip_head(const unsigned char *packet,headinfo *h_info);

inline void decode_udp_head(const unsigned char *packet,headinfo *h_info);


inline void decode_tcp_head(const unsigned char *packet,headinfo *h_info);