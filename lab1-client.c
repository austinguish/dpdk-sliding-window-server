/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include "udp_header.h"
#include <inttypes.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

// #define PKT_TX_IPV4          (1ULL << 55)
// #define PKT_TX_IP_CKSUM      (1ULL << 54)

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_FLOW_NUM 100
#define PORT_NUM 5001
uint32_t NUM_PING = 100;

/* Define the mempool globally */
struct rte_mempool* mbuf_pool = NULL;
static struct rte_ether_addr my_eth;
static size_t message_size = 1000;
static uint32_t seconds = 1;

size_t window_len = 1;
size_t max_send = 100;

int flow_size = 10000;
int packet_len = 1000;
int flow_num = 1;

struct flow_state
{
    uint16_t next_seq_to_send;
    uint16_t last_ack_received;
    uint16_t last_sent;
    uint16_t window_size;
    uint16_t peer_window_size;
    uint16_t effective_window_size;
    struct rte_ring* unacked_packets;
    struct rte_ring* unsent_packets;
} flow_states[MAX_FLOW_NUM];

void init_flow_state()
{
    for (int i = 0; i < flow_num; i++)
    {
        flow_states[i].next_seq_to_send = 0;
        flow_states[i].last_ack_received = 0;
        flow_states[i].last_sent = 0;
        flow_states[i].window_size = window_len;
        flow_states[i].peer_window_size = window_len;
        flow_states[i].effective_window_size = RTE_MIN(window_len, flow_states[i].peer_window_size);
        flow_states[i].unacked_packets = rte_ring_create(
            "unacked_packets", NUM_MBUFS, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        flow_states[i].unsent_packets = rte_ring_create(
            "unsent_packets", NUM_MBUFS, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
}


static uint64_t raw_time(void)
{
    struct timespec tstart = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    uint64_t t = (uint64_t)(tstart.tv_sec * 1.0e9 + tstart.tv_nsec);
    return t;
}

static uint64_t time_now(uint64_t offset) { return raw_time() - offset; }

uint32_t checksum(unsigned char* buf, uint32_t nbytes, uint32_t sum)
{
    unsigned int i;

    /* Checksum all the pairs of bytes first. */
    for (i = 0; i < (nbytes & ~1U); i += 2)
    {
        sum += (uint16_t)ntohs(*((uint16_t *)(buf + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    if (i < nbytes)
    {
        sum += buf[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    return sum;
}

uint32_t wrapsum(uint32_t sum)
{
    sum = ~sum & 0xFFFF;
    return htons(sum);
}

static int parse_packet(struct sockaddr_in* src, struct sockaddr_in* dst,
                        void** payload, size_t* payload_len,
                        struct rte_mbuf* pkt)
{
    // packet layout order is (from outside -> in):
    // ether_hdr
    // ipv4_hdr
    // udp_hdr
    // client timestamp
    uint8_t* p = rte_pktmbuf_mtod(pkt, uint8_t *);
    size_t header = 0;

    // check the ethernet header
    struct rte_ether_hdr* const eth_hdr = (struct rte_ether_hdr*)(p);
    p += sizeof(*eth_hdr);
    header += sizeof(*eth_hdr);
    uint16_t eth_type = ntohs(eth_hdr->ether_type);
    struct rte_ether_addr mac_addr = {};

    rte_eth_macaddr_get(1, &mac_addr);
    if (!rte_is_same_ether_addr(&mac_addr, &eth_hdr->dst_addr))
    {
        printf("Bad MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 "\n",
               eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
               eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
               eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
        return -1;
    }
    if (RTE_ETHER_TYPE_IPV4 != eth_type)
    {
        printf("Bad ether type\n");
        return -2;
    }

    // check the IP header
    struct rte_ipv4_hdr* const ip_hdr = (struct rte_ipv4_hdr*)(p);
    p += sizeof(*ip_hdr);
    header += sizeof(*ip_hdr);

    // In network byte order.
    in_addr_t ipv4_src_addr = ip_hdr->src_addr;
    in_addr_t ipv4_dst_addr = ip_hdr->dst_addr;

    if (IPPROTO_UDP != ip_hdr->next_proto_id)
    {
        printf("Bad next proto_id\n");
        return -3;
    }

    src->sin_addr.s_addr = ipv4_src_addr;
    dst->sin_addr.s_addr = ipv4_dst_addr;

    // check udp header
    struct udp_header_extra* const udp_hdr_ext = (struct udp_header_extra*)(p);
    printf("Received packet with window size %u\n", udp_hdr_ext->window_size);

    max_send = udp_hdr_ext->window_size;
    // set
    p += sizeof(*udp_hdr_ext);
    header += sizeof(*udp_hdr_ext);

    // In network byte order.
    in_port_t udp_src_port = udp_hdr_ext->udp_hdr.src_port;
    in_port_t udp_dst_port = udp_hdr_ext->udp_hdr.dst_port;
    // print out the port number
    printf("Received packet with src port %u and dst port %u\n",
           rte_be_to_cpu_16(udp_hdr_ext->udp_hdr.src_port),
           rte_be_to_cpu_16(udp_hdr_ext->udp_hdr.dst_port));

    int ret = rte_be_to_cpu_16(udp_hdr_ext->udp_hdr.dst_port) - PORT_NUM;
    if (ret < 0 || ret >= MAX_FLOW_NUM)
    {
        printf("Bad port number %d\n",
               rte_be_to_cpu_16(udp_hdr_ext->udp_hdr.dst_port));
        return -4;
    }

    src->sin_port = udp_src_port;
    dst->sin_port = udp_dst_port;

    src->sin_family = AF_INET;
    dst->sin_family = AF_INET;

    *payload_len = pkt->pkt_len - header;
    *payload = (void*)p;
    return ret;
}

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port, struct rte_mempool* mbuf_pool)
{
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
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
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n", port,
               strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++)
    {
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

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 "\n",
           port, RTE_ETHER_ADDR_BYTES(&my_eth));

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}

static struct rte_mbuf* create_packet(uint16_t port_id, struct flow_state* flow, struct rte_ether_addr dst,
                                      uint16_t packet_len)
{
    struct rte_mbuf* pkt = rte_pktmbuf_alloc(mbuf_pool);
    if (pkt == NULL)
    {
        rte_exit(EXIT_FAILURE, "Failed to allocate packet\n");
    }

    uint8_t* ptr = rte_pktmbuf_mtod(pkt, uint8_t *);
    size_t header_size = 0;

    /* add in an ethernet header */
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)ptr;
    rte_ether_addr_copy(&my_eth, &eth_hdr->src_addr);
    rte_ether_addr_copy(&dst, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);
    ptr += sizeof(*eth_hdr);
    header_size += sizeof(*eth_hdr);

    /* add in ipv4 header*/
    struct rte_ipv4_hdr* ipv4_hdr = (struct rte_ipv4_hdr*)ptr;
    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0x0;
    ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
        sizeof(struct udp_header_extra) + packet_len);
    ipv4_hdr->packet_id = rte_cpu_to_be_16(1);
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
    ipv4_hdr->src_addr = rte_cpu_to_be_32(0x0A000001); // 10.0.0.1
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(0x0A000002); // 10.0.0.2

    uint32_t ipv4_checksum = wrapsum(
        checksum((unsigned char*)ipv4_hdr, sizeof(struct rte_ipv4_hdr), 0));
    ipv4_hdr->hdr_checksum = rte_cpu_to_be_32(ipv4_checksum);
    header_size += sizeof(*ipv4_hdr);
    ptr += sizeof(*ipv4_hdr);

    /* add in UDP hdr*/
    struct udp_header_extra* udp_hdr_ext = (struct udp_header_extra*)ptr;
    uint16_t srcp = PORT_NUM + port_id;
    uint16_t dstp = PORT_NUM + port_id;
    udp_hdr_ext->window_size = rte_cpu_to_be_16(flow->window_size);
    udp_hdr_ext->seq = rte_cpu_to_be_16(flow->next_seq_to_send);
    udp_hdr_ext->udp_hdr.src_port = rte_cpu_to_be_16(srcp);
    udp_hdr_ext->udp_hdr.dst_port = rte_cpu_to_be_16(dstp);
    udp_hdr_ext->udp_hdr.dgram_len = rte_cpu_to_be_16(sizeof(struct udp_header_extra) + packet_len);

    uint16_t udp_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, (void*)udp_hdr_ext);
    udp_hdr_ext->udp_hdr.dgram_cksum = rte_cpu_to_be_16(udp_cksum);
    ptr += sizeof(*udp_hdr_ext);
    header_size += sizeof(*udp_hdr_ext);

    // Set payload
    memset(ptr, 0, packet_len);
    uint64_t timestamp = time_now(0);
    memcpy(ptr, &timestamp, sizeof(timestamp));
    printf("Created packet with timestamp %" PRIu64 " and sequence number %u\n", timestamp, flow->next_seq_to_send);

    // Set packet metadata
    pkt->l2_len = RTE_ETHER_HDR_LEN;
    pkt->l3_len = sizeof(struct rte_ipv4_hdr);
    pkt->data_len = header_size + packet_len;
    pkt->pkt_len = header_size + packet_len;
    pkt->nb_segs = 1;

    return pkt;
}

/* >8 End of main functional part of port initialization. */
/* >8 End Basic forwarding application lcore. */
static void send_packet(struct rte_ether_addr dst,
                        size_t port_id)
{
    // todo handle the unsent packets
    struct flow_state* flow = &flow_states[port_id];

    // 计算当前可以发送的数据量
    uint16_t in_flight = flow->next_seq_to_send - flow->last_ack_received;
    uint16_t available_window = flow->effective_window_size > in_flight ? flow->effective_window_size - in_flight : 0;

    if (available_window > 0)
    {
        struct rte_mbuf* pkt_to_send = NULL;

        // 首先尝试从 unsent_packets 中获取数据包
        if (rte_ring_dequeue(flow->unsent_packets, (void**)&pkt_to_send) != 0)
        {
            // 如果 unsent_packets 为空，创建新的数据包
            pkt_to_send = create_packet(port_id, flow, dst, packet_len);
        }

        if (pkt_to_send != NULL)
        {
            int pkts_sent = rte_eth_tx_burst(1, 0, &pkt_to_send, 1);
            if (pkts_sent == 1)
            {
                printf("Sent packet of size %u with sequence number %u\n",
                       (unsigned)pkt_to_send->pkt_len, flow->next_seq_to_send);
                flow->last_sent = flow->next_seq_to_send;
                flow->next_seq_to_send++;

                // 将数据包存储在 unacked_packets 中
                rte_ring_enqueue(flow->unacked_packets, pkt_to_send);
            }
            else
            {
                // 如果发送失败，将数据包放回 unsent_packets
                rte_ring_enqueue(flow->unsent_packets, pkt_to_send);
            }
        }
    }
    else
    {
        printf("Window full, cannot send more packets\n");
    }

    /* set the payload */

    //uint64_t last_sent = rte_get_timer_cycles();
}

static void receive(uint16_t port_id)
{
    struct flow_state* flow = &flow_states[port_id];
    struct rte_mbuf* pkts[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, pkts, BURST_SIZE);

    for (int i = 0; i < nb_rx; i++)
    {
        struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
        struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
        struct udp_header_extra* udp_hdr_ext = (struct udp_header_extra*)(ip_hdr + 1);

        uint16_t seq_num = rte_be_to_cpu_16(udp_hdr_ext->seq);
        uint16_t received_window_size = rte_be_to_cpu_16(udp_hdr_ext->window_size);

        // Check if this is a data packet or an ACK

        // This is an ACK
        printf("Received ACK for sequence number %u\n", seq_num);

        // Update last_ack_received if this ACK is newer
        if (seq_num > flow->last_ack_received)
        {
            flow->last_ack_received = seq_num;
            printf("Updated last_ack_received to %u\n", flow->last_ack_received);
            flow->peer_window_size = received_window_size;
            flow->effective_window_size = RTE_MIN(flow->window_size, flow->peer_window_size);
            printf("Updated peer window size to %u, effective window size to %u\n",
                   flow->peer_window_size, flow->effective_window_size);
            // Remove acknowledged packets from unacked_packets ring
            struct rte_mbuf* acked_pkt;
            while (rte_ring_dequeue(flow->unacked_packets, (void**)&acked_pkt) == 0)
            {
                struct udp_header_extra* acked_udp_hdr = rte_pktmbuf_mtod_offset(acked_pkt, struct udp_header_extra *,
                    sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
                uint16_t acked_seq = rte_be_to_cpu_16(acked_udp_hdr->seq);

                if (acked_seq < flow->last_ack_received)
                {
                    rte_pktmbuf_free(acked_pkt);
                }
                else
                {
                    rte_ring_enqueue(flow->unacked_packets, acked_pkt);
                    break;
                }
            }


            // Update window size
            flow->peer_window_size = received_window_size;
            printf("Updated peer window size to %u\n", flow->peer_window_size);
        }

        rte_pktmbuf_free(pkts[i]);
    }
}

static void lcore_main()
{
    init_flow_state();
    // Specify the dst mac address here:
    struct rte_ether_addr dst = {{0xec, 0xb1, 0xD7, 0x85, 0x7a, 0x63}};
    // uint64_t cycle_wait = intersend_time * rte_get_timer_hz() / (1e9);

    // TODO: add in scaffolding for timing/printing out quick statistics
    printf("flow num is %d\n", flow_num);
    size_t port_id = 0;

    while (flow_states[port_id].next_seq_to_send < NUM_PING)
    {
        send_packet(dst, port_id);
        printf("sent a packet!\n");
        /* now poll on receiving packets */
        receive(port_id);

        port_id = (port_id + 1) % flow_num;
    }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */

int main(int argc, char* argv[])
{
    unsigned nb_ports;
    uint16_t portid;

    if (argc == 3)
    {
        flow_num = (int)atoi(argv[1]);
        flow_size = (int)atoi(argv[2]);
    }
    else
    {
        printf("usage: ./lab1-client <flow_num> <flow_size>\n");
        return 1;
    }

    NUM_PING = flow_size / packet_len;

    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    argc -= ret;
    argv += ret;

    nb_ports = rte_eth_dev_count_avail();
    printf("Number of available ports: %u\n", nb_ports);
    /* Allocates mempool to hold the mbufs. 8< */
    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    /* >8 End of allocating mempool to hold mbuf. */

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initializing all ports. 8< */
    RTE_ETH_FOREACH_DEV(portid)
        if (portid == 1 && port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    /* >8 End of initializing all ports. */

    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    /* Call lcore_main on the main core only. Called on single lcore. 8< */
    lcore_main();
    /* >8 End of called on single lcore. */
    printf("Done!\n");
    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
