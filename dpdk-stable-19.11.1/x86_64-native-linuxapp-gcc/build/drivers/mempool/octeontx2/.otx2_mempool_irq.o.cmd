cmd_otx2_mempool_irq.o = gcc -Wp,-MD,./.otx2_mempool_irq.o.d.tmp  -m64 -pthread -I/home/wurp/dpdk-stable-19.11.1/lib/librte_eal/linux/eal/include  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_RDSEED -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/home/wurp/dpdk-stable-19.11.1/x86_64-native-linuxapp-gcc/include -DRTE_USE_FUNCTION_VERSIONING -include /home/wurp/dpdk-stable-19.11.1/x86_64-native-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wno-address-of-packed-member -I/home/wurp/dpdk-stable-19.11.1/drivers/common/octeontx2 -I/home/wurp/dpdk-stable-19.11.1/drivers/mempool/octeontx2 -I/home/wurp/dpdk-stable-19.11.1/drivers/bus/pci -O3 -DALLOW_EXPERIMENTAL_API    -o otx2_mempool_irq.o -c /home/wurp/dpdk-stable-19.11.1/drivers/mempool/octeontx2/otx2_mempool_irq.c 
