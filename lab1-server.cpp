/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>

#include "udp_header.h"
#include <rte_common.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include "flowstate.h"
#include <rte_launch.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_FLOW_NUM 100
#define PORT_NUM 5001

struct rte_mempool *mbuf_pool = NULL;
static struct rte_ether_addr my_eth;
size_t window_len = 10;
struct flow_state_receiver *global_flow_state;

struct thread_args {
    uint16_t queue_id;
    rte_mempool *mbuf_pool;
};

int flow_size = 10000;
int packet_len = 1000;
int ack_len = 10;
int flow_num = 12;
using namespace std;
const bool UNFINISHED = true;

rte_mbuf *create_ack(struct rte_mbuf *pkt, uint16_t new_window);
int reconfigure_queues(uint16_t port_id, uint16_t new_queue_count) {
    int ret;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf = {0};

    // Stop the Ethernet port
    rte_eth_dev_stop(port_id);

    // Get the current device info
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        printf("Error during getting device (port %u) info: %s\n",
               port_id, strerror(-ret));
        return ret;
    }

    // Configure the Ethernet device with new queue count
    ret = rte_eth_dev_configure(port_id, new_queue_count, new_queue_count, &port_conf);
    if (ret != 0) {
        printf("Failed to configure device: err=%d, port=%u\n", ret, port_id);
        return ret;
    }

    // Setup RX and TX queues
    for (uint16_t q = 0; q < new_queue_count; q++) {
        ret = rte_eth_rx_queue_setup(port_id, q, RX_RING_SIZE,
                                     rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
        if (ret < 0) {
            printf("Failed to setup RX queue: err=%d, port=%u\n", ret, port_id);
            return ret;
        }

        ret = rte_eth_tx_queue_setup(port_id, q, TX_RING_SIZE,
                                     rte_eth_dev_socket_id(port_id), NULL);
        if (ret < 0) {
            printf("Failed to setup TX queue: err=%d, port=%u\n", ret, port_id);
            return ret;
        }
    }

    // Start the Ethernet port
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        printf("Failed to start port %u: %s\n", port_id, strerror(-ret));
        return ret;
    }

    printf("Successfully reconfigured port %u with %u queues\n", port_id, new_queue_count);
    return 0;
}


uint32_t
checksum(unsigned char *buf, uint32_t nbytes, uint32_t sum) {
    unsigned int i;

    /* Checksum all the pairs of bytes first. */
    for (i = 0; i < (nbytes & ~1U); i += 2) {
        sum += (uint16_t) ntohs(*((uint16_t *)(buf + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    if (i < nbytes) {
        sum += buf[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    return sum;
}

uint32_t
wrapsum(uint32_t sum) {
    sum = ~sum & 0xFFFF;
    return htons(sum);
}

static uint64_t raw_time(void) {
    struct timespec tstart = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    uint64_t t = (uint64_t) (tstart.tv_sec * 1.0e9 + tstart.tv_nsec);
    return t;
}

static uint64_t time_now(uint64_t offset) { return raw_time() - offset; }

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 12, tx_rings = 12;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
               port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
                RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    retval = rte_eth_macaddr_get(port, &my_eth);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
           port, RTE_ETHER_ADDR_BYTES(&my_eth));

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}

/* >8 End of main functional part of port initialization. */

void init_flow_states() {
    global_flow_state = new flow_state_receiver();
    global_flow_state->advertised_window.store(WINDOW_SIZE);

    for (int i = 0; i < flow_num; i++) {
        global_flow_state->flow_states[i] = new flow_state();
        global_flow_state->flow_states[i]->next_seq_num_expected = 1;
        global_flow_state->flow_states[i]->last_read = 0;
        global_flow_state->flow_states[i]->last_received = 0;
    }
}

static int get_port(struct sockaddr_in *src,
                    struct sockaddr_in *dst,
                    void **payload,
                    size_t *payload_len,
                    struct rte_mbuf *pkt) {
    // packet layout order is (from outside -> in):
    // ether_hdr
    // ipv4_hdr
    // udp_hdr
    // client timestamp
    uint8_t *p = rte_pktmbuf_mtod(pkt, uint8_t *);
    size_t header = 0;

    // check the ethernet header
    struct rte_ether_hdr *const eth_hdr = (struct rte_ether_hdr *) (p);
    p += sizeof(*eth_hdr);
    header += sizeof(*eth_hdr);
    uint16_t eth_type = ntohs(eth_hdr->ether_type);
    struct rte_ether_addr mac_addr = {};
    rte_eth_macaddr_get(1, &mac_addr);
    if (!rte_is_same_ether_addr(&mac_addr, &eth_hdr->dst_addr)) {
        // printf("Bad MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
        //     " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
        //     eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
        //  eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
        //  eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
        return -1;
    }
    if (RTE_ETHER_TYPE_IPV4 != eth_type) {
        printf("Bad ether type\n");
        return -2;
    }

    // check the IP header
    struct rte_ipv4_hdr *const ip_hdr = (struct rte_ipv4_hdr *) (p);
    p += sizeof(*ip_hdr);
    header += sizeof(*ip_hdr);

    // In network byte order.
    in_addr_t ipv4_src_addr = ip_hdr->src_addr;
    in_addr_t ipv4_dst_addr = ip_hdr->dst_addr;

    if (IPPROTO_UDP != ip_hdr->next_proto_id) {
        printf("Bad next proto_id\n");
        return -3;
    }

    src->sin_addr.s_addr = ipv4_src_addr;
    dst->sin_addr.s_addr = ipv4_dst_addr;

    // check udp header

    struct udp_header_extra *const udp_hdr_ext = (struct udp_header_extra *) (p);
    p += sizeof(*udp_hdr_ext);
    header += sizeof(*udp_hdr_ext);

    // In network byte order.
    in_port_t udp_src_port = udp_hdr_ext->udp_hdr.src_port;
    in_port_t udp_dst_port = udp_hdr_ext->udp_hdr.dst_port;

    int ret = rte_be_to_cpu_16(udp_hdr_ext->udp_hdr.dst_port) - PORT_NUM;
    if (ret < 0 || ret >= MAX_FLOW_NUM) {
        printf("Bad port number %d\n", rte_be_to_cpu_16(udp_hdr_ext->udp_hdr.dst_port));
        return -4;
    }

    src->sin_port = udp_src_port;
    dst->sin_port = udp_dst_port;

    src->sin_family = AF_INET;
    dst->sin_family = AF_INET;

    *payload_len = pkt->pkt_len - header;
    *payload = (void *) p;
    // print the received time stamp in the payload
    // the data is uint64_t
    //print out
    // printf("Received timestamp: %" PRIu64 "\n", payload);
    return ret;
}

static uint16_t get_flow_id(struct rte_mbuf *pkt) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *) (eth_hdr + 1);
    struct udp_header_extra *udp_hdr = (struct udp_header_extra *) (ip_hdr + 1);

    return rte_be_to_cpu_16(udp_hdr->udp_hdr.dst_port) - PORT_NUM;
}

static int wait_for_initialization_packet(uint16_t port) {
    struct rte_mbuf *pkt;

    while (1) {
        if (rte_eth_rx_burst(port, 0, &pkt, 1) > 0) {
            struct udp_header_extra *udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct udp_header_extra *,
                                                                       sizeof(struct rte_ether_hdr) + sizeof(struct
                                                                           rte_ipv4_hdr));

            if (udp_hdr->seq == 0) {
                uint8_t *payload = (uint8_t *) (udp_hdr + 1);
                flow_num = *(int *) payload;
                init_flow_states();
                // Send ACK for initialization packet
                struct rte_mbuf *ack_pkt = create_ack(pkt, WINDOW_SIZE);
                if (ack_pkt != NULL) {
                    rte_eth_tx_burst(port, 0, &ack_pkt, 1);
                }

                rte_pktmbuf_free(pkt);
                return 0;
            }
            rte_pktmbuf_free(pkt);
        }
    }
    return -1;
}

/* Basic forwarding application lcore. 8< */
static int lcore_main(void *arg) {
    // unsigned lcore_id = rte_lcore_id();
    uint16_t port = 1; // Assuming we're using port 1
    // auto *lcore_id = (uint16_t*)args;
    auto *args = (thread_args *) arg;
    auto queue_id = args->queue_id;
    printf("Core %u handling packets\n", queue_id);

    while (1) {
        struct rte_mbuf *bufs[BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(port, queue_id, bufs, BURST_SIZE);
        if (nb_rx >= 1) {
            printf("receive %d from queue %d\n", nb_rx, queue_id);
        }


        for (int i = 0; i < nb_rx; i++) {
            struct rte_mbuf *pkt = bufs[i];
            uint16_t flow_id = get_flow_id(pkt);

            if (flow_id >= flow_num) {
                rte_pktmbuf_free(pkt);
                continue;
            }

            flow_state *current_flow = global_flow_state->flow_states[flow_id];
            struct udp_header_extra *udp_h = rte_pktmbuf_mtod_offset(pkt, struct udp_header_extra *,
                                                                     sizeof(struct rte_ether_hdr) + sizeof(struct
                                                                         rte_ipv4_hdr));

            current_flow->last_received = std::max(current_flow->last_received, udp_h->seq);

            if (udp_h->seq == current_flow->next_seq_num_expected) {
                current_flow->next_seq_num_expected++;
                while (current_flow->window_packets.count(current_flow->next_seq_num_expected) > 0) {
                    current_flow->next_seq_num_expected++;
                    // current_flow->window_packets.erase(current_flow->next_seq_num_expected - 1);
                }
            } else if (udp_h->seq > current_flow->next_seq_num_expected) {
                current_flow->window_packets[udp_h->seq] = pkt;
                continue;
            }

            uint16_t packets_in_flight = current_flow->next_seq_num_expected - current_flow->last_read - 1;
            uint16_t new_window = WINDOW_SIZE - packets_in_flight;
            global_flow_state->advertised_window.store(new_window, std::memory_order_relaxed);

            struct rte_mbuf *ack = create_ack(pkt, new_window);

            uint16_t nb_tx = 0;
            if (ack != NULL) {
                nb_tx = rte_eth_tx_burst(port, queue_id, &ack, 1);
            }

            printf("saa %d from queue: %d\n",nb_tx, queue_id);

            current_flow->last_read = udp_h->seq;
            rte_pktmbuf_free(pkt);
        }
    }

    return 0;
}

rte_mbuf *create_ack(struct rte_mbuf *pkt, uint16_t new_window) {
    rte_mbuf *ack = rte_pktmbuf_alloc(mbuf_pool);
    if (ack == NULL) {
        printf("Error allocating tx mbuf\n");
        return NULL;
    }

    size_t header_size = 0;
    auto eth_h = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    auto ip_h = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *,
                                        sizeof(struct rte_ether_hdr));
    auto udp_h = rte_pktmbuf_mtod_offset(pkt, struct udp_header_extra *,
                                         sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    uint8_t *ptr = rte_pktmbuf_mtod(ack, uint8_t *);

    /* add in an ethernet header */
    auto eth_h_ack = reinterpret_cast<struct rte_ether_hdr *>(ptr);
    rte_ether_addr_copy(&my_eth, &eth_h_ack->src_addr);
    rte_ether_addr_copy(&eth_h->src_addr, &eth_h_ack->dst_addr);
    eth_h_ack->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    ptr += sizeof(*eth_h_ack);
    header_size += sizeof(*eth_h_ack);

    /* add in ipv4 header*/
    auto ip_h_ack = reinterpret_cast<struct rte_ipv4_hdr *>(ptr);
    ip_h_ack->version_ihl = 0x45;
    ip_h_ack->type_of_service = 0x0;
    ip_h_ack->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct udp_header_extra) + ack_len);
    ip_h_ack->packet_id = htons(1);
    ip_h_ack->fragment_offset = 0;
    ip_h_ack->time_to_live = 64;
    ip_h_ack->next_proto_id = IPPROTO_UDP;
    ip_h_ack->src_addr = ip_h->dst_addr;
    ip_h_ack->dst_addr = ip_h->src_addr;
    ip_h_ack->hdr_checksum = 0; // Will be filled by hardware
    header_size += sizeof(*ip_h_ack);
    ptr += sizeof(*ip_h_ack);

    /* add in UDP hdr*/
    auto udp_h_ack_ext = reinterpret_cast<struct udp_header_extra *>(ptr);
    auto udp_h_ack = &udp_h_ack_ext->udp_hdr;
    udp_h_ack->src_port = udp_h->udp_hdr.dst_port;
    udp_h_ack->dst_port = udp_h->udp_hdr.src_port;
    udp_h_ack->dgram_len = htons(sizeof(struct udp_header_extra) + ack_len);
    udp_h_ack_ext->window_size = new_window; // Use the passed new_window value
    udp_h_ack_ext->seq = udp_h->seq;
    udp_h_ack_ext->send_time = udp_h->send_time;
    udp_h_ack->dgram_cksum = 0; // Will be filled by hardware or calculated later
    header_size += sizeof(*udp_h_ack_ext);
    ptr += sizeof(*udp_h_ack_ext);

    /* set the payload */
    memset(ptr, 'a', ack_len);

    ack->l2_len = RTE_ETHER_HDR_LEN;
    ack->l3_len = sizeof(struct rte_ipv4_hdr);
    ack->l4_len = sizeof(struct udp_header_extra);
    // ack->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
    ack->data_len = header_size + ack_len;
    ack->pkt_len = header_size + ack_len;
    ack->nb_segs = 1;

    // Calculate UDP checksum
    udp_h_ack->dgram_cksum = rte_ipv4_udptcp_cksum(ip_h_ack, udp_h_ack);

    return ack;
}

/* >8 End Basic forwarding application lcore. */

int launch_workers(uint16_t flow_num) {
    unsigned int lcore_id;
    uint16_t workers_launched = 0;
    thread_args *args = (thread_args *)malloc(sizeof(thread_args) * flow_num);
    if (args == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to allocate memory for thread arguments\n");
    }

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (workers_launched >= flow_num) {
            break;  // We've launched enough workers
        }

        // thread_args *args = malloc(sizeof(thread_args));
        // if (args == NULL) {
        //     printf("Failed to allocate memory for thread arguments\n");
        //     return -1;
        // }

        args->queue_id = workers_launched;
        args->mbuf_pool = mbuf_pool;  // Assuming mbuf_pool is a global variable

        int ret = rte_eal_remote_launch(lcore_main, args, lcore_id);
        if (ret != 0) {
            printf("Failed to launch lcore %u\n", lcore_id);
            free(args);
            return -1;
        }

        printf("Launched worker on lcore %u with queue_id %u\n", lcore_id+1, workers_launched);
        workers_launched++;
    }

    if (workers_launched < flow_num) {
        printf("Warning: Could only launch %u workers, but %u flows were requested\n",
               workers_launched, flow_num);
    }

    return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {
    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret;
    argv += ret;
    unsigned nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1) rte_exit(EXIT_FAILURE, "Error: no available ports\n");
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    uint16_t portid = 1; // Assuming we're using port 1
    if (port_init(portid, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    printf("Waiting for initialization packet...\n");
    // if (wait_for_initialization_packet(portid) != 0)
        // rte_exit(EXIT_FAILURE, "Failed to receive initialization packet\n");
    init_flow_states();
    // printf("Initialization complete. Flow number set to: %d\n", flow_num);
    // if (reconfigure_queues(portid, flow_num) != 0) {
    //     rte_exit(EXIT_FAILURE, "Failed to reconfigure queues\n");
    // }

    uint16_t lcore_count = 0;


    // RTE_LCORE_FOREACH_WORKER(lcore_count) {
    //     if (lcore_count > flow_num) break;
    //     args[lcore_count].queue_id = lcore_count;
    //     rte_eal_remote_launch(lcore_main, &args[lcore_count], lcore_count);
    // }
    if (launch_workers(flow_num) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to launch workers\n");
    }

    rte_eal_mp_wait_lcore();
    // free(args);
    rte_eal_cleanup();
    return 0;


}
