#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdint.h>
#include <stdio.h>
// Platform headers
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define NUM_MBUFS       (4096-1)
#define MBUF_CACHE_SIZE 0

#define TX_RING_SIZE    1024
//#define RX_RING_SIZE    1024

// Everyone seems to use 32. Nobody seems to know why.
#define BURST_SIZE      32
#define DPDK_QUEUE_ID_TX 0


#define MAKE_IPV4_ADDR(a, b, c, d)  (a + (b<<8) + (c<<16) + (d<<24))
static uint32_t g_src_ip = MAKE_IPV4_ADDR(192, 168, 2, 143);
static uint32_t g_dest_ip = MAKE_IPV4_ADDR(192, 168, 2, 142);
// PC mac
static uint8_t g_dest_mac_addr[RTE_ETHER_ADDR_LEN] = { 0xf0, 0x76, 0x1c, 0xee, 0xb1, 0xa1 };
// DPDK mac
//static uint8_t g_dest_mac_addr[RTE_ETHER_ADDR_LEN] = { 0x00, 0x0c, 0x29, 0x3d, 0xfc, 0xc8 };

static uint8_t g_src_mac_addr[RTE_ETHER_ADDR_LEN]; 


// In DPDK, a "port" is a NIC. We will use the first NIC DPDK finds.
int g_dpdkPortId = -1;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
};

#if 0
static inline void 
port_init(uint16_t port, struct rte_mempool *mbuf_pool) {

    while (port < RTE_MAX_ETHPORTS &&
	       rte_eth_devices[port].data->owner.id != RTE_ETH_DEV_NO_OWNER) {
		port++;
    }
    if (port == RTE_MAX_ETHPORTS) {
        rte_exit(EXIT_FAILURE, "There were no DPDK ports free.\n");
    }

	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf local_port_conf = port_conf_default;
	
	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	
 	
    // Configure the Ethernet device.
    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    //struct rte_eth_conf port_conf = port_conf_default;
    if (rte_eth_dev_configure(port, num_rx_queues, num_tx_queues, &local_port_conf)) {
        rte_exit(EXIT_FAILURE, "rte_eth_dev_configure() failed.\n");
    }

	uint16_t nb_txd = TX_RING_SIZE;
	uint16_t nb_rxd = TX_RING_SIZE;
	rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	
	
	struct rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
	if (rte_eth_rx_queue_setup(port, 0, nb_rxd,
            rte_eth_dev_socket_id(port), &rxq_conf, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Couldn't setup RX queue.\n");
    }
	
	
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
	
    // Set up TX queue.
    if (rte_eth_tx_queue_setup(port, 0, nb_txd,
            rte_eth_dev_socket_id(port), &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Couldn't setup TX queue.\n");
    }
	
    // Start the Ethernet port.
    if (rte_eth_dev_start(port) < 0) {
        rte_exit(EXIT_FAILURE, "Device start failed.\n");
    }

	
	rte_eth_promiscuous_enable(port);
}
#endif

inline static uint16_t
gen_checksum(const char *buf, int num_bytes) {
    const uint16_t *half_words = (const uint16_t *)buf;
    unsigned sum = 0;
    for (int i = 0; i < num_bytes / 2; i++)
        sum += half_words[i];

    if (num_bytes & 1)
        sum += buf[num_bytes - 1];

    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum & 0xff0000) >> 16;
    sum = ~sum & 0xffff;

    return sum;
}


inline static void
port_init(struct rte_mempool *mbuf_pool) {

    g_dpdkPortId = 0;
    while (g_dpdkPortId < RTE_MAX_ETHPORTS &&
	       rte_eth_devices[g_dpdkPortId].data->owner.id != RTE_ETH_DEV_NO_OWNER) {
		g_dpdkPortId++;
    }
    if (g_dpdkPortId == RTE_MAX_ETHPORTS) {
        rte_exit(EXIT_FAILURE, "There were no DPDK ports free.\n");
    }

	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf local_port_conf = port_conf_default;
	
	rte_eth_dev_info_get(g_dpdkPortId, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	
 	
    // Configure the Ethernet device.
    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    //struct rte_eth_conf port_conf = port_conf_default;
    if (rte_eth_dev_configure(g_dpdkPortId, num_rx_queues, num_tx_queues, &local_port_conf)) {
        rte_exit(EXIT_FAILURE, "rte_eth_dev_configure() failed.\n");
    }

	uint16_t nb_txd = TX_RING_SIZE;
	uint16_t nb_rxd = TX_RING_SIZE;
	rte_eth_dev_adjust_nb_rx_tx_desc(g_dpdkPortId, &nb_rxd, &nb_txd);
	
	
	struct rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
	// Set up RX queue
	if (rte_eth_rx_queue_setup(g_dpdkPortId, 0, nb_rxd,
            rte_eth_dev_socket_id(g_dpdkPortId), &rxq_conf, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Couldn't setup RX queue.\n");
    }
	
	
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
    // Set up TX queue.
    if (rte_eth_tx_queue_setup(g_dpdkPortId, 0, nb_txd,
            rte_eth_dev_socket_id(g_dpdkPortId), &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Couldn't setup TX queue.\n");
    }
	
    // Start the Ethernet port.
    if (rte_eth_dev_start(g_dpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Device start failed.\n");
    }

    // get port mac address
    struct rte_ether_addr mac_addr;
    rte_eth_macaddr_get(g_dpdkPortId, &mac_addr);
    printf("Port[%u] MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n", g_dpdkPortId,
           mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
           mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
           mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);    
	
	rte_eth_promiscuous_enable(g_dpdkPortId);
}

static void
create_eth_ip_udp(uint8_t *msg, size_t total_len, uint8_t dst_mac[RTE_ETHER_ADDR_LEN],
    uint32_t src_ip, uint32_t dst_ip, uint16_t udp_src_port, uint16_t udp_dst_port) {
    // Packet looks like this:
    //   Eth  |  IP  |  UDP  |  <payload>

    // Ethernet hdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    // udp dst mac/src mac
    memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    memcpy(eth->s_addr.addr_bytes, g_src_mac_addr, RTE_ETHER_ADDR_LEN);
    // udp frame tyep
    eth->ether_type = htons(ETH_P_IP);

    // (eth+1) offset length of rte_ether_hdr
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    size_t ip_len = total_len - sizeof(struct rte_ether_hdr);
#if 0
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)ip_len);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    ip->check = gen_checksum((char *)ip, sizeof(struct iphdr));
#endif
    // version&ihl
    ip->version_ihl = 0x45;
    // tos
    ip->type_of_service = 0x0;
    // tot_len
    ip->total_length = htons((uint16_t)ip_len);
    // id
    ip->packet_id = 0;
    // frag_off
    ip->fragment_offset = 0;
    // ttl
    ip->time_to_live = 0x40;
    // protocol
    ip->next_proto_id = IPPROTO_UDP;
    // check: have to init 0 to cacl the number
    ip->hdr_checksum = 0;
    // saddr
    ip->src_addr = src_ip;
    // daddr
    ip->dst_addr = dst_ip;
    // check
    ip->hdr_checksum = gen_checksum((char *)ip, sizeof(struct rte_ipv4_hdr));

#if 0  
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    size_t udp_len = ip_len - sizeof(struct iphdr);
    udp->source = htons(udp_src_port);
    udp->dest = htons(udp_dst_port);
    udp->len = htons((uint16_t)udp_len);
#endif
    // (ip+1) offset length of rte_ipv4_hdr
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
    size_t udp_len = ip_len - sizeof(struct rte_ipv4_hdr);
    udp->src_port = htons(udp_src_port);
    udp->dst_port = htons(udp_dst_port);
    udp->dgram_len = htons((uint16_t)udp_len); 
    // Set the UDP checksum to zero for simplicity. This is perfectly legal. It
    // just tells the the receiver not to check the checksum.
    udp->dgram_cksum = 0;

    // Use the packet count as the payload.
    // (udp+1) offset length of rte_udp_hdr to get the payload.
    uint32_t *payload = (uint32_t *)(udp + 1);
    static uint32_t seq_num = 0;
    *payload = htonl(seq_num++);
}


inline static void
do_send(struct rte_mempool *mbuf_pool, int num_to_send) {
    // The smallest packet allowed by Ethernet. (64~1518bytes.)
    const unsigned eth_total_len = 64;

    struct rte_mbuf *mbufs[BURST_SIZE];
    for (int i = 0; i < BURST_SIZE; ++i) {
        mbufs[i] = rte_pktmbuf_alloc(mbuf_pool);
        if (!mbufs[i]) {
            rte_exit(EXIT_FAILURE, "Cannot alloc mbuf\n");
        }

        mbufs[i]->pkt_len = eth_total_len; // smallest 64bytes.
        mbufs[i]->data_len = eth_total_len;
    }


    for (int num_packets_left = num_to_send; num_packets_left > 0; ) {
        int num_to_send_this_burst = BURST_SIZE;
        if (num_packets_left < BURST_SIZE) {
            // adjust number to send this burst to number of packets left.
            num_to_send_this_burst = num_packets_left;
        }

        for (int i = 0; i < num_to_send_this_burst; ++i) {
            // A macro that points to the start of the data in the mbuf.
            uint8_t *packet_data = rte_pktmbuf_mtod(mbufs[i], uint8_t *);
            
            const int UDP_PORT = 8080; // 9096
            create_eth_ip_udp(packet_data, eth_total_len, 
                g_dest_mac_addr, g_src_ip, g_dest_ip, UDP_PORT, UDP_PORT);
        }

        int num_sent = rte_eth_tx_burst(g_dpdkPortId, DPDK_QUEUE_ID_TX, mbufs, num_to_send_this_burst);

        printf("Sent %i packets\n", num_sent);
        num_packets_left -= num_sent;
        
    }
}


int
main(int argc, char *argv[]) {
    // Initialize the Environment Abstraction Layer. All DPDK apps must do this.
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL Init.\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, 
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Couldn't create mbuf pool.\n");
    }

    port_init(mbuf_pool);
    printf("\n\nInit port success.\n");

    rte_eth_macaddr_get(g_dpdkPortId, (struct rte_ether_addr *)g_src_mac_addr);
    printf("Our MAC: %02x %02x %02x %02x %02x %02x\n",
            g_src_mac_addr[0], g_src_mac_addr[1],
            g_src_mac_addr[2], g_src_mac_addr[3],
            g_src_mac_addr[4], g_src_mac_addr[5]);

    do_send(mbuf_pool, 1);
    
    return 0;
}

