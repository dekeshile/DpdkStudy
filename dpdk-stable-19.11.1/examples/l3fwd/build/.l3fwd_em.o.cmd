cmd_l3fwd_em.o = gcc -Wp,-MD,./.l3fwd_em.o.d.tmp  -m64 -pthread -I/home/wurp/dpdk-stable-19.11.1/lib/librte_eal/linux/eal/include  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_RDSEED -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/home/wurp/dpdk-stable-19.11.1/examples/l3fwd/build/include -DRTE_USE_FUNCTION_VERSIONING -I/home/wurp/dpdk-stable-19.11.1/x86_64-native-linuxapp-gcc/include -include /home/wurp/dpdk-stable-19.11.1/x86_64-native-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -I/home/wurp/dpdk-stable-19.11.1/examples/l3fwd -O3  -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wno-address-of-packed-member    -o l3fwd_em.o -c /home/wurp/dpdk-stable-19.11.1/examples/l3fwd/l3fwd_em.c 
