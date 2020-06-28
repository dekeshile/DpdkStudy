#ifndef _KNI_H_
#define _KNI_H_
struct lcore_params {
	uint16_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;
#define PORT_KNI_NUMS 6
extern int numa_on; /**< NUMA is enabled by default. */
extern struct rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS][8];
extern int per_port_pool; /**< Use separate buffer pools per port; disabled */
			  /**< by default */
extern struct lcore_params * lcore_params;
extern uint16_t nb_lcore_params;
extern int kni();
extern int free_kni();

extern void kni_status_init(uint16_t port_id,uint8_t queueid);
extern int kni_status_change(uint16_t port_id);
extern void kni_ingress_nonuma(uint16_t port_id,uint8_t queueid);
extern void kni_ingress_numa(uint16_t port_id,uint8_t queueid,int socketid);
extern int pause_kni();
extern void printf_kni_status();
#endif