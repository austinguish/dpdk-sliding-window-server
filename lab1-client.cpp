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
// preset flow_state_sender pointer arrays
struct flow_state_sender* flow_table[MAX_FLOW_NUM];
// uint16_t next_seq_num;  // last packet sent
//    uint16_t effective_window;
//    struct rte_mbuf *window_packets[WINDOW_SIZE];
//    uint64_t send_times[WINDOW_SIZE];
//    int last_acked; // acked packets
//    // last written to the window
//    uint16_t last_written; // last packet send to window

const rte_ether_addr dst = {{0x14, 0x58, 0xD0, 0x58, 0xee, 0xa3}};

void init_flow_table()
{
    for (int i = 0; i < flow_num; i++)
    {
        flow_table[i] = (struct flow_state_sender*)malloc(sizeof(struct flow_state_sender));
        struct flow_state_sender* sender = flow_table[i];
        sender->next_seq_num = 1;
        sender->effective_window = window_len;
        sender->last_acked = 0;
        sender->last_written = 0;
        sender->advertised_window = WINDOW_SIZE;
        // use std map to store the unacked packets
        sender->unacked_packets = std::map<int, struct rte_mbuf*>();
        sender->unacked_seq = std::queue<int>();
        // save the pointer to the flow state table
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
    rte_ether_hdr* eth_hdr = (rte_ether_hdr*)ptr;
    rte_ether_addr_copy(&my_eth, &eth_hdr->src_addr);
    // Assuming dst is a global variable, you might need to pass it as a parameter
    rte_ether_addr_copy(&dst, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    ptr += sizeof(*eth_hdr);
    header_size += sizeof(*eth_hdr);

    // IPv4 header
    rte_ipv4_hdr* ipv4_hdr = (rte_ipv4_hdr*)ptr;
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
    udp_header_extra* udp_hdr_ext = (udp_header_extra*)ptr;
    uint16_t srcp = PORT_NUM + flow_id;
    uint16_t dstp = PORT_NUM + flow_id;
    udp_hdr_ext->window_size = rte_cpu_to_be_16(flow_num);
    udp_hdr_ext->udp_hdr.src_port = rte_cpu_to_be_16(srcp);
    udp_hdr_ext->udp_hdr.dst_port = rte_cpu_to_be_16(dstp);
    udp_hdr_ext->udp_hdr.dgram_len = rte_cpu_to_be_16(sizeof(udp_header_extra) + packet_len);
    udp_hdr_ext->udp_hdr.dgram_cksum = 0; // Will be filled by hardware
    udp_hdr_ext->seq = rte_cpu_to_be_16(seq_num); // Add sequence number
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

/* >8 End of main functional part of port initialization. */

/* >8 End Basic forwarding application lcore. */
static void send_packet(int flow_id)
{
    flow_state_sender* state = flow_table[flow_id];
    rte_mbuf* pkt;
    int pkts_sent = 0;

    // Calculate packets in flight
    uint32_t packets_in_flight = state->next_seq_num - state->last_acked - 1;

    // Calculate available window in packets
    uint32_t available_window = state->advertised_window > packets_in_flight
                                    ? state->advertised_window - packets_in_flight
                                    : 0;

    // Determine how many packets we can send
    uint32_t packets_to_send = std::min(available_window,
                                        (uint32_t)(NUM_PING - state->last_written));

    while (packets_to_send > 0)
    {
        pkt = rte_pktmbuf_alloc(mbuf_pool);
        if (pkt == nullptr)
        {
            printf("Error allocating tx mbuf\n");
            return;
        }

        prepare_packet(pkt, flow_id, state->next_seq_num);
        pkts_sent = rte_eth_tx_burst(1, 0, &pkt, 1);
        if (pkts_sent == 1)
        {
            state->unacked_packets[state->next_seq_num] = pkt;
            state->unacked_seq.push(state->next_seq_num);
            state->next_seq_num++;
            state->last_written++;
            packets_to_send--;
        }
        else
        {
            rte_pktmbuf_free(pkt);
            break; // Stop if we couldn't send a packet
        }
    }

    // state->last_send_time = rte_get_timer_cycles();
}

void receive_and_process_acks()
{
    rte_mbuf* pkts[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(1, 0, pkts, BURST_SIZE);

    for (uint16_t i = 0; i < nb_rx; i++)
    {
        sockaddr_in src, dst;
        void* payload = nullptr;
        size_t payload_length = 0;
        int ack_num = 0;
        uint16_t advertised_window = 0;

        int flow_id = parse_packet(&src, &dst, &payload, &payload_length, pkts[i], &ack_num, &advertised_window);
        if (flow_id >= 0 && flow_id < MAX_FLOW_NUM)
        {
            flow_state_sender* state = flow_table[flow_id];

            // Update the advertised window (in packets)
            state->advertised_window = advertised_window;

            if (ack_num >= state->last_acked)
            {
                // Process ACK
                if (ack_num > state->last_acked)
                {
                    // New ACK received
                    int acked_packets = ack_num - state->last_acked;
                    state->in_flight_packets -= acked_packets;

                    while (!state->unacked_seq.empty() && state->unacked_seq.front() <= ack_num)
                    {
                        int seq = state->unacked_seq.front();
                        state->unacked_seq.pop();
                        rte_pktmbuf_free(state->unacked_packets[seq]);
                        state->unacked_packets.erase(seq);
                    }
                    state->last_acked = ack_num;
                    // state->duplicate_acks = 0; // Reset duplicate ACK counter
                    // } else {
                    //     // Duplicate ACK received
                    //     state->duplicate_acks++;
                    //     if (state->duplicate_acks == 3) {
                    //         // Fast retransmit
                    //         // Retransmit the packet with sequence number last_acked + 1
                    //         // This part needs to be implemented
                    //     }
                    // }

                    // Update the effective window (in packets)
                    state->effective_window = (state->advertised_window > state->in_flight_packets)
                                                  ? (state->advertised_window - state->in_flight_packets)
                                                  : 0;
                }
            }
            rte_pktmbuf_free(pkts[i]);
        }
    }
}

static void lcore_main()
{
    struct rte_mbuf* pkts[BURST_SIZE];
    struct rte_mbuf* pkt;
    // char *buf_ptr;
    struct rte_ether_hdr* eth_hdr;
    struct rte_ipv4_hdr* ipv4_hdr;
    struct rte_udp_hdr* udp_hdr;

    // Specify the dst mac address here:

    struct sliding_hdr* sld_h_ack;
    uint16_t nb_rx;
    uint64_t reqs = 0;
    // uint64_t cycle_wait = intersend_time * rte_get_timer_hz() / (1e9);

    // TODO: add in scaffolding for timing/printing out quick statistics
    printf("flow num is %d\n", flow_num);
    int flow_id = 0;
    while (true)
    {
        // Send packets for all flows
        for (flow_id = 0; flow_id < flow_num; flow_id++)
        {
            send_packet(flow_id);
        }

        // Receive and process ACKs
        receive_and_process_acks();

        // Check if all flows are complete
        bool all_complete = true;
        for (flow_id = 0; flow_id < flow_num; flow_id++)
        {
            if (flow_table[flow_id]->last_written < NUM_PING - 1 || !flow_table[flow_id]->unacked_packets.empty())
            {
                all_complete = false;
                break;
            }
        }
        if (all_complete)
        {
            break;
        }
    }
}

// while (flow_table[flow_id]->last_written < NUM_PING)
// {
//     send_packet(flow_id);
//     printf("sent a packet!\n");
//     /* now poll on receiving packets */
//     receive(&nb_rx, pkts, flow_id);
//
//     flow_id = (flow_id + 1) % flow_num;
// }
// printf("Sent %" PRIu64 " packets.\n", reqs);

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
    // init the flow_state_table
    init_flow_table();
    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    argc -= ret;
    argv += ret;

    nb_ports = rte_eth_dev_count_avail();
    printf("the number of nb_ports is %d", nb_ports);
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
    // clean the flow_state_table
    for (int i = 0; i < flow_num; i++)
    {
        free(flow_table[i]);
    }
    return 0;
}
