

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>


#include <stdio.h>

#include <linux/if_ether.h>

#include <arpa/inet.h>
/*
#include <netinet/ip.h>
#include <netinet/udp.h>
*/

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define UDP_PORT	8080

#define MBUF_CACHE_SIZE 0

#define BURST_SIZE 32

#define DPDK_QUEUE_ID_RX 0

int g_dpdkPortId = -1;
struct rte_kni *kni = NULL;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t g_src_ip = MAKE_IPV4_ADDR(192, 168, 2, 143);
static uint32_t g_dest_ip = MAKE_IPV4_ADDR(192, 168, 2, 142);
static uint8_t g_dest_mac_addr[RTE_ETHER_ADDR_LEN] = { 0xf0, 0x76, 0x1c, 0xee, 0xb1, 0xa1 };


//static uint32_t g_src_ip = MAKE_IPV4_ADDR(192, 168, 0, 120);
//static uint32_t g_dest_ip = MAKE_IPV4_ADDR(192, 168, 0, 113);
//static uint8_t g_dest_mac_mac_addr[RTE_ETHER_ADDR_LEN] = {0xEC, 0xF4, 0xBB, 0x4A, 0xA3, 0xB2};//{ 0x00, 0x0c, 0x29, 0x18, 0xef, 0x9d };
static uint8_t g_src_mac_addr[RTE_ETHER_ADDR_LEN];

static void port_init(struct rte_mempool *mbuf_pool) {

    g_dpdkPortId = 0;
	
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");
	
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf local_port_conf = port_conf_default;
	
	rte_eth_dev_info_get(g_dpdkPortId, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    if (rte_eth_dev_configure(g_dpdkPortId, num_rx_queues, num_tx_queues, &port_conf)) {
        rte_exit(EXIT_FAILURE, "rte_eth_dev_configure() failed.\n");
    }
	
	uint16_t nb_txd = TX_RING_SIZE;
	uint16_t nb_rxd = RX_RING_SIZE;
	rte_eth_dev_adjust_nb_rx_tx_desc(g_dpdkPortId, &nb_rxd, &nb_txd);

    // Set up RX queue.
    struct rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
    if (rte_eth_rx_queue_setup(g_dpdkPortId, DPDK_QUEUE_ID_RX, RX_RING_SIZE,
            rte_eth_dev_socket_id(g_dpdkPortId), &rxq_conf, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Couldn't setup RX queue.\n");
    }
	
	// Set up TX queue.
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
	if (rte_eth_tx_queue_setup(g_dpdkPortId, 0, nb_txd,
            rte_eth_dev_socket_id(g_dpdkPortId), &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Couldn't setup TX queue.\n");
    }

    // Start the Ethernet port.
    if (rte_eth_dev_start(g_dpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Device start failed.\n");
    }

    // Enable RX in promiscuous mode for the Ethernet device.
    rte_eth_promiscuous_enable(g_dpdkPortId);
}


static void create_eth_ip_udp_pkt(uint8_t *msg, size_t total_len, uint8_t *dst_mac,
    uint32_t src_ip, uint32_t dst_ip, uint16_t udp_src_port, uint16_t udp_dst_port, 
    uint8_t *data, int length) {

	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->s_addr.addr_bytes, g_src_mac_addr, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(ETH_P_IP);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    size_t ip_len = total_len - sizeof(struct rte_ether_hdr);
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons((uint16_t)ip_len);
    ip->packet_id = 0;
	ip->fragment_offset = 0;
    ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_UDP;
	
	ip->src_addr = src_ip;
	ip->dst_addr = dst_ip;
	
	ip->hdr_checksum = 0;
    ip->hdr_checksum =  rte_ipv4_cksum(ip);

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
    //size_t udp_len = ip_len - sizeof(struct rte_ipv4_hdr);
    udp->src_port = htons(udp_src_port);
    udp->dst_port = htons(udp_dst_port);
    udp->dgram_len = htons((uint16_t)(length + sizeof(struct rte_udp_hdr)));

    uint32_t *payload = (uint32_t *)(udp + 1);
    rte_memcpy(payload, data, length);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

}


static void do_send(struct rte_mempool *mbuf_pool, unsigned char *data, int length) {

	const unsigned eth_total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "Cannot alloc mbuf\n");
	}

	mbuf->pkt_len = eth_total_len;
    mbuf->data_len = eth_total_len;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	const int udp_port = UDP_PORT;

	create_eth_ip_udp_pkt(pkt_data, eth_total_len, g_dest_mac_addr, 
		g_src_ip, g_dest_ip, udp_port, udp_port, data, length);

	rte_eth_tx_burst(g_dpdkPortId, 0, &mbuf, 1);

	rte_pktmbuf_free(mbuf);

}



int main(int argc, char *argv[]) {
    // Initialize the Environment Abstraction Layer. All DPDK apps must do this.
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    // Creates a new mempool in memory to hold the mbufs.
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Couldn't create mbuf pool\n");
    }
	printf("rte_pktmbuf_pool_create\n");
	
    port_init(mbuf_pool);
	rte_eth_macaddr_get(g_dpdkPortId, (struct rte_ether_addr*)g_src_mac_addr);

    while (1) { 

        struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(g_dpdkPortId, DPDK_QUEUE_ID_RX, mbufs, BURST_SIZE);
		if (unlikely(num_recvd > BURST_SIZE)) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}

		int i = 0;
		for (i = 0;i < num_recvd;i ++) {
			
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue ;
			}

			struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
			if (ip_hdr->next_proto_id == IPPROTO_UDP) {
                struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *) ((unsigned char *) ip_hdr + sizeof(struct rte_ipv4_hdr));
                if (UDP_PORT == ntohs(udp_hdr->src_port)) {
                    printf("Received packet: ");
    				
    				uint16_t length = ntohs(udp_hdr->dgram_len);
    				*((char *)udp_hdr + length) = '\0';
    				
                    struct in_addr addr;
    				addr.s_addr = ip_hdr->src_addr;
    				printf("kni_ingress src: %s:%d", inet_ntoa(addr), ntohs(udp_hdr->src_port));

    				addr.s_addr = ip_hdr->dst_addr;
                    printf(", dst: %s:%d --> length:%d, %s\n", inet_ntoa(addr), ntohs(udp_hdr->dst_port), length, (char *)(udp_hdr+1));

    				if (UDP_PORT == ntohs(udp_hdr->src_port))
    					do_send(mbuf_pool, (unsigned char *)(udp_hdr+1), length-8);
                }
			}
            rte_pktmbuf_free(mbufs[i]);
		}

    }

    return 0;
}
