cmd_dpaa_ethdev.o = gcc -Wp,-MD,./.dpaa_ethdev.o.d.tmp  -I/home/wurp/dpdk-stable-19.11.1/drivers/net/dpaa -m64 -pthread -I/home/wurp/dpdk-stable-19.11.1/lib/librte_eal/linux/eal/include  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_RDSEED -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/home/wurp/dpdk-stable-19.11.1/x86_64-native-linuxapp-gcc/include -DRTE_USE_FUNCTION_VERSIONING -include /home/wurp/dpdk-stable-19.11.1/x86_64-native-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -O3 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wno-address-of-packed-member -Wno-pointer-arith -I/home/wurp/dpdk-stable-19.11.1/drivers/net/dpaa/ -I/home/wurp/dpdk-stable-19.11.1/drivers/net/dpaa/include -I/home/wurp/dpdk-stable-19.11.1/drivers/bus/dpaa -I/home/wurp/dpdk-stable-19.11.1/drivers/bus/dpaa/include/ -I/home/wurp/dpdk-stable-19.11.1/drivers/bus/dpaa/base/qbman -I/home/wurp/dpdk-stable-19.11.1/drivers/mempool/dpaa -I/home/wurp/dpdk-stable-19.11.1/drivers/common/dpaax -I/home/wurp/dpdk-stable-19.11.1/drivers/event/dpaa -I/home/wurp/dpdk-stable-19.11.1/lib/librte_eal/common/include -DALLOW_EXPERIMENTAL_API    -o dpaa_ethdev.o -c /home/wurp/dpdk-stable-19.11.1/drivers/net/dpaa/dpaa_ethdev.c 
