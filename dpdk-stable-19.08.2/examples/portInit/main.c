#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>

#define RX_RING_SIZE    1024
#define TX_RING_SIZE    1024

#define NUM_MBUFS (4096-1)
#define MBUF_CACHE_SIZE 250


// port default configure
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
};

// port init
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    int ret;
    uint16_t q;
    struct rte_eth_conf port_conf = port_conf_default;

    // number of rx/tx rings
    const uint16_t rx_rings = 1;
    const uint16_t tx_rings = 0;

    // number of rx/tx descriptor
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;

    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port)) {
        return -1;
    }
    
    // get port info
    rte_eth_dev_info_get(port, &dev_info);
    
    printf("\n\ninitializing port %d...\n", port);
    
    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret != 0) {
        return ret;
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (ret != 0) {
        return ret;
   }

    // 分配RX队列
    for (q = 0; q < rx_rings; ++q) {
        ret = rte_eth_rx_queue_setup(port, q, nb_rxd,
            rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (ret < 0) {
            return ret;
        }
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    // 分配TX队列
    for (q = 0; q < tx_rings; ++q) {
        ret = rte_eth_tx_queue_setup(port, q, nb_txd,
            rte_eth_dev_socket_id(port), &txconf);
    }
   
    // 使能接口
    if (rte_eth_dev_start(port) < 0) {
        rte_exit(EXIT_FAILURE, "Could not start.\n");
    }

    // get port mac address
    struct rte_ether_addr mac_addr;
    rte_eth_macaddr_get(port, &mac_addr);


    printf("Port[%u] MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
           port,
           mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
           mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
           mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);

    //打开混杂模式
    rte_eth_promiscuous_enable(port);

    return 0;
}

int main(int argc, char * argv []) {
    unsigned nb_ports;
    uint16_t portid;

    // EAL init
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }
    printf("\n\n\n*****************************************\n");

    // Numbers of ports
    nb_ports = rte_eth_dev_count_avail();
    printf("number of available port: %d\n", nb_ports);
    
    // Mbuf pool
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, 
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (NULL == mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    // Initialize all ports
    RTE_ETH_FOREACH_DEV(portid)
    if (port_init(portid, mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                 portid);
    }
//    while (1) {
//        
//    }
    
    return 0;
    
}


