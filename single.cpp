//
// Created by jiangyw on 24-9-23.
//
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
#include "flowstate.h"
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <vector>
#include <rte_flow.h>
#include <rte_ethdev.h>
#define MAX_QUEUES 128
rte_atomic64_t tx_packet_count[MAX_QUEUES];
rte_atomic64_t rx_packet_count[MAX_QUEUES];
// predefine the flowstatetable here

// #define PKT_TX_IPV4          (1ULL << 55)
// #define PKT_TX_IP_CKSUM      (1ULL << 54)

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_FLOW_NUM 100
#define PORT_NUM 5001
#define MAX_PATTERN_NUM 8
#define MAX_ACTION_NUM 2
uint32_t NUM_PING = 100;

/* Define the mempool globally */
rte_mempool* mbuf_pool = NULL;
static rte_ether_addr my_eth;
// static size_t message_size = 1000;
// static uint32_t seconds = 1;

size_t window_len = 1;
size_t max_send = 100;

int flow_size = 10000;
int packet_len = 1000;
int flow_num = 1;
// preset flow_state_sender pointer arrays
flow_state_sender* flow_table[MAX_FLOW_NUM];
// uint16_t next_seq_num;  // last packet sent
//    uint16_t effective_window;
//    struct rte_mbuf *window_packets[WINDOW_SIZE];
//    uint64_t send_times[WINDOW_SIZE];
//    int last_acked; // acked packets
//    // last written to the window
//    uint16_t last_written; // last packet send to window

const rte_ether_addr dst = {{0x14, 0x58, 0xD0, 0x58, 0xdf, 0x43}};
struct thread_args
{
    uint16_t queue_id;
    rte_mempool* mbuf_pool;
};

static int initialize_flows(uint16_t port, int flow_num)
{
    rte_mbuf* pkt;
    rte_ether_hdr* eth_hdr;
    rte_ipv4_hdr* ip_hdr;
    udp_header_extra* udp_hdr_ext;
    uint8_t* payload;

    // Allocate a new mbuf for the initialization packet
    pkt = rte_pktmbuf_alloc(mbuf_pool);
    if (pkt == NULL)
    {
        rte_exit(EXIT_FAILURE, "Failed to allocate mbuf for initialization\n");
    }

    // Prepare the packet
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ip_hdr = (rte_ipv4_hdr*)(eth_hdr + 1);
    udp_hdr_ext = (udp_header_extra*)(ip_hdr + 1);
    payload = (uint8_t*)(udp_hdr_ext + 1);

    // Fill in the headers (similar to prepare_packet function)
    // Ethernet header
    rte_ether_addr_copy(&my_eth, &eth_hdr->src_addr);
    rte_ether_addr_copy(&dst, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // IP header
    ip_hdr->version_ihl = 0x45;
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = rte_cpu_to_be_16(sizeof(*ip_hdr) + sizeof(*udp_hdr_ext) + sizeof(int));
    ip_hdr->packet_id = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = IPPROTO_UDP;
    ip_hdr->src_addr = rte_cpu_to_be_32(0x0A000001); // 10.0.0.1
    ip_hdr->dst_addr = rte_cpu_to_be_32(0x0A000002); // 10.0.0.2
    ip_hdr->hdr_checksum = 0; // Will be filled by hardware

    // UDP header
    udp_hdr_ext->udp_hdr.src_port = rte_cpu_to_be_16(PORT_NUM);
    udp_hdr_ext->udp_hdr.dst_port = rte_cpu_to_be_16(PORT_NUM);
    udp_hdr_ext->udp_hdr.dgram_len = rte_cpu_to_be_16(sizeof(*udp_hdr_ext) + sizeof(int));
    udp_hdr_ext->udp_hdr.dgram_cksum = 0; // Will be filled by hardware
    udp_hdr_ext->seq = 0; // Special sequence number for initialization
    udp_hdr_ext->window_size = rte_cpu_to_be_16(flow_num); // Send flow_num as window_size

    // Payload (flow_num)
    *(int*)payload = flow_num;

    // Set packet length
    pkt->pkt_len = pkt->data_len = sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr_ext) + sizeof(int);

    // Send the packet
    if (rte_eth_tx_burst(port, 0, &pkt, 1) != 1)
    {
        printf("Failed to send initialization packet\n");
        rte_pktmbuf_free(pkt);
        return -1;
    }

    // Wait for ACK
    rte_mbuf* rx_pkts[1];
    int retry_count = 0;
    while (retry_count < 10)
    {
        // Try 10 times before giving up
        if (rte_eth_rx_burst(port, 0, rx_pkts, 1) > 0)
        {
            // Process the received packet (you may want to add more checks here)
            printf("Received ACK for initialization\n");
            rte_pktmbuf_free(rx_pkts[0]);
            return 0; // Success
        }
        rte_delay_ms(100); // Wait for 100ms before retrying
        retry_count++;
    }

    printf("Failed to receive ACK for initialization\n");
    return -1;
}

std::vector<flow_state_sender> flows;

static void init_flows(int num_flows) {
    flows.resize(num_flows);
    for (auto& flow : flows) {
        flow.next_seq_num = 1;
        flow.effective_window = WINDOW_SIZE;
        flow.advertised_window = WINDOW_SIZE;
        flow.last_acked = 0;
        flow.last_written = 0;
        flow.in_flight_packets = 0;
        flow.successfully_acked = 0;
        flow.finished = false;
    }
}

static uint64_t raw_time(void)
{
    timespec tstart = {0, 0};
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
        sum += (uint16_t)ntohs(*((uint16_t*)(buf + i)));
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

static void prepare_packet(rte_mbuf* pkt, const int flow_id, uint16_t seq_num)
{
    size_t header_size = 0;
    uint8_t* ptr = rte_pktmbuf_mtod(pkt, uint8_t*);

    // Ethernet header
    auto* eth_hdr = (rte_ether_hdr*)ptr;
    rte_ether_addr_copy(&my_eth, &eth_hdr->src_addr);
    // Assuming dst is a global variable, you might need to pass it as a parameter
    rte_ether_addr_copy(&dst, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    ptr += sizeof(*eth_hdr);
    header_size += sizeof(*eth_hdr);

    // IPv4 header
    auto* ipv4_hdr = (rte_ipv4_hdr*)ptr;
    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0x0;
    ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(rte_ipv4_hdr) +
        sizeof(udp_header_extra) +
        packet_len);
    ipv4_hdr->packet_id = rte_cpu_to_be_16(1);
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
    ipv4_hdr->src_addr = rte_cpu_to_be_32(0x0A000001); // 10.0.0.1
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(0x0A000002); // 10.0.0.2
    ipv4_hdr->hdr_checksum = 0; // Will be filled by hardware
    ptr += sizeof(*ipv4_hdr);
    header_size += sizeof(*ipv4_hdr);

    // UDP header
    auto* udp_hdr_ext = (udp_header_extra*)ptr;
    uint16_t srcp = PORT_NUM + flow_id;
    uint16_t dstp = PORT_NUM + flow_id;
    udp_hdr_ext->window_size = rte_cpu_to_be_16(flow_num);
    udp_hdr_ext->udp_hdr.src_port = rte_cpu_to_be_16(srcp);
    udp_hdr_ext->udp_hdr.dst_port = rte_cpu_to_be_16(dstp);
    udp_hdr_ext->udp_hdr.dgram_len = rte_cpu_to_be_16(sizeof(udp_header_extra) + packet_len);
    udp_hdr_ext->udp_hdr.dgram_cksum = 0; // Will be filled by hardware
    udp_hdr_ext->seq = seq_num; // Add sequence number
    ptr += sizeof(*udp_hdr_ext);
    header_size += sizeof(*udp_hdr_ext);

    // Payload
    memset(ptr, 0, packet_len);
    uint64_t timestamp = time_now(0);
    memcpy(ptr, &timestamp, sizeof(timestamp));

    // Set packet attributes
    pkt->nb_segs = 1;
    pkt->pkt_len = header_size + packet_len;
    pkt->data_len = pkt->pkt_len;
    pkt->l2_len = RTE_ETHER_HDR_LEN;
    pkt->l3_len = sizeof(struct rte_ipv4_hdr);
    pkt->l4_len = sizeof(struct udp_header_extra);
    // pkt->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
}


static int parse_packet(struct sockaddr_in* src, struct sockaddr_in* dst,
                        void** payload, size_t* payload_len,
                        struct rte_mbuf* pkt, int* ack_num, uint16_t* advertised_window)
{
    // packet layout order is (from outside -> in):
    // ether_hdr
    // ipv4_hdr
    // udp_hdr
    // client timestamp
    uint8_t* p = rte_pktmbuf_mtod(pkt, uint8_t *);
    size_t header = 0;

    // check the ethernet header
    auto* const eth_hdr = (struct rte_ether_hdr*)(p);
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
    auto* const ip_hdr = (rte_ipv4_hdr*)(p);
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
    auto* const udp_hdr_ext = (udp_header_extra*)(p);
    // printf("Received packet with window size %u\n", udp_hdr_ext->window_size);
    max_send = udp_hdr_ext->window_size;
    // set
    p += sizeof(*udp_hdr_ext);
    header += sizeof(*udp_hdr_ext);

    // In network byte order.
    in_port_t udp_src_port = udp_hdr_ext->udp_hdr.src_port;
    in_port_t udp_dst_port = udp_hdr_ext->udp_hdr.dst_port;
    // set the ack number
    *ack_num = udp_hdr_ext->seq;
    *advertised_window = udp_hdr_ext->window_size;

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
    rte_eth_conf port_conf;
    const uint16_t rx_rings =1,tx_rings =1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    rte_eth_dev_info dev_info;
    rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
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

    /* Allocate and set up RX queues */
    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up TX queues */
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    retval = rte_eth_macaddr_get(port, &my_eth);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
           port, RTE_ETHER_ADDR_BYTES(&my_eth));

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    return 0;
}

/* >8 End of main functional part of port initialization. */

/* >8 End Basic forwarding application lcore. */
static void send_packets(uint16_t port_id) {
    for (size_t i = 0; i < flows.size(); ++i) {
        auto& flow = flows[i];
        if (flow.finished) continue;

        uint32_t packets_in_flight = flow.next_seq_num - flow.last_acked - 1;
        uint32_t available_window = flow.advertised_window > packets_in_flight
                                    ? flow.advertised_window - packets_in_flight
                                    : 0;
        uint32_t packets_to_send = std::min(available_window,
                                            (uint32_t)(NUM_PING - flow.last_written));

        std::vector<struct rte_mbuf*> tx_pkts;
        for (uint32_t j = 0; j < packets_to_send; ++j) {
            struct rte_mbuf* pkt = rte_pktmbuf_alloc(mbuf_pool);
            if (pkt == NULL) {
                printf("Error allocating tx mbuf for flow %zu\n", i);
                break;
            }

            prepare_packet(pkt, i, flow.next_seq_num);
            tx_pkts.push_back(pkt);

            flow.unacked_packets[flow.next_seq_num] = pkt;
            flow.unacked_seq.push(flow.next_seq_num);
            flow.next_seq_num++;
            flow.last_written++;
            flow.in_flight_packets++;
        }

        uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, tx_pkts.data(), tx_pkts.size());
        if (nb_tx < tx_pkts.size()) {
            for (uint16_t j = nb_tx; j < tx_pkts.size(); ++j) {
                rte_pktmbuf_free(tx_pkts[j]);
            }
        }
    }
}
static void receive_packets(uint16_t port_id) {
    struct rte_mbuf* rx_pkts[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, rx_pkts, BURST_SIZE);

    for (uint16_t i = 0; i < nb_rx; ++i) {
        sockaddr_in src, dst;
        void* payload = nullptr;
        size_t payload_length = 0;
        int ack_num = 0;
        uint16_t advertised_window = 0;

        int flow_id = parse_packet(&src, &dst, &payload, &payload_length, rx_pkts[i], &ack_num, &advertised_window);

        if (flow_id >= 0 && flow_id < flows.size()) {
            auto& flow = flows[flow_id];
            flow.advertised_window = advertised_window;

            if (ack_num >= flow.last_acked) {
                if (ack_num > flow.last_acked) {
                    int newly_acked = ack_num - flow.last_acked;
                    flow.successfully_acked += newly_acked;  // 更新成功确认的包计数
                    flow.in_flight_packets -= newly_acked;

                    while (!flow.unacked_seq.empty() && flow.unacked_seq.front() <= ack_num) {
                        int seq = flow.unacked_seq.front();
                        flow.unacked_seq.pop();
                        rte_pktmbuf_free(flow.unacked_packets[seq]);
                        flow.unacked_packets.erase(seq);
                    }
                    flow.last_acked = ack_num;

                    flow.effective_window = (flow.advertised_window > flow.in_flight_packets)
                                            ? (flow.advertised_window - flow.in_flight_packets)
                                            : 0;
                }
            }

            // 检查是否所有包都已确认接收
            if (flow.successfully_acked >= NUM_PING) {
                flow.finished = true;
                printf("Flow %d finished. Successfully acked %u packets.\n", flow_id, flow.successfully_acked);
            }
        } else {
            printf("Received packet for invalid flow_id %d\n", flow_id);
        }

        rte_pktmbuf_free(rx_pkts[i]);
    }
}

static int lcore_main(void* arg)
{
     while (true) {
            send_packets(1);  // Assuming port 1 is used
            receive_packets(1);

            bool all_finished = true;
            for (const auto& flow : flows) {
                if (!flow.finished) {
                    all_finished = false;
                    break;
                }
            }

            if (all_finished) {
                printf("All flows finished\n");
                break;
            }
        }

        return 0;
}


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
    init_flows(flow_num);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    nb_ports = rte_eth_dev_count_avail();
    printf("the number of nb_ports is %d\n", nb_ports);

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports * flow_num,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                        rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    RTE_ETH_FOREACH_DEV(portid)
        if (portid == 1 && port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    // if (initialize_flows(1, flow_num) != 0)
    // {
    //     rte_exit(EXIT_FAILURE, "Failed to initialize flows with server\n");
    // }
    // check how many queues on port 1 tx and rx
    rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(1, &dev_info);

    printf("Port 1: RX queues = %u, TX queues = %u\n",
           dev_info.nb_rx_queues,
           dev_info.nb_tx_queues);
    thread_args args[flow_num];

    ret = lcore_main(NULL);
    rte_eal_cleanup();
    return 0;
}
