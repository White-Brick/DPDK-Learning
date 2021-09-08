

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32

int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

/** 收发包接口初始化 */
static void ng_init_port(struct rte_mempool *mbuf_pool) {

	uint16_t nb_sys_ports= rte_eth_dev_count_avail(); // 获取系统接口数量
	printf("Number of available port: %d\n", nb_sys_ports);
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	struct rte_eth_dev_info dev_info;
#if 0
	/** 循环获取网卡个数以及相应信息 */
	int portid;
	int ret;
	for （portid = 0; portid < nb_sys_ports; ++portid） {
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Cannot get device info: err=%d, port=%d\n",
				ret, portid);
		}
		printf("port: %d Driver: %s\n", portid, dev_info.driver_name);
	}

	/** 获取接口mac地址 */
	static struct rte_ether_addr ports_eth_addr[MAX_PORTS];
	for （portid = 0; portid < nb_sys_ports; ++portid） {
		ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Cannot get Mac address: err=%d, port=%d\n",
				ret, portid);
		}
		char mac[18];
		rte_ether_format_addr(&mac[0], 18, &ports_eth_addr[portid]);
		printf("port: %d->MAC-> %s\n", portid, mac);
	}
#endif
	rte_eth_dev_info_get(gDpdkPortId, &dev_info); // 获取device info
	
	const int num_rx_queues = 1;
	const int num_tx_queues = 1;
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);


	if (rte_eth_rx_queue_setup(gDpdkPortId, 0 , 128, 
		rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {

		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

	}

	if (rte_eth_tx_queue_setup(gDpdkPortId, 0 , 128, 
		rte_eth_dev_socket_id(gDpdkPortId), NULL) < 0) {

		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

	}

	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

	rte_eth_promiscuous_enable(gDpdkPortId);	

}











int main(int argc, char *argv[]) {

	/** 初始化EAL */
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

	ng_init_port(mbuf_pool);

	while (1) {

		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}

		//rte_eth_tx_burst
			
		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				rte_pktmbuf_free(mbufs[i]);
				continue;
			}

			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			
			if (iphdr->next_proto_id == IPPROTO_UDP) {

				struct rte_udp_hdr *udphdr = 
					(struct rte_udp_hdr *)((unsigned char*)iphdr + sizeof(struct rte_ipv4_hdr));

				if (ntohs( udphdr->dst_port) == 8888 ) {
					uint16_t length = ntohs(udphdr->dgram_len);
					*(((char*)udphdr) + length) = '\0';

					struct in_addr addr;
					addr.s_addr = iphdr->src_addr;
					printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

					addr.s_addr = iphdr->dst_addr;
					printf("dst: %s:%d, length:%d --> %s\n", inet_ntoa(addr), 
						ntohs(udphdr->src_port), length, (char *)(udphdr+1));
				}

				rte_pktmbuf_free(mbufs[i]);
			}
			
		}

	}

}




