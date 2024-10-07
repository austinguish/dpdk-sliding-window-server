//
// Created by tianyi on 24-10-7.
//

#ifndef FLOWSTATE_H
#define FLOWSTATE_H
#define WINDOW_SIZE 1024
#include <queue>
#include<map>
struct flow_state_sender {
    uint16_t next_seq_num;  // last packet sent
    uint16_t effective_window;
    // struct rte_mbuf *window_packets[WINDOW_SIZE];
    // use queue<int> to store the unacked seq
    std::map<int, struct rte_mbuf *> unacked_packets;
    uint64_t send_times[WINDOW_SIZE];
    int last_acked; // acked packets
    // last written to the window
    uint16_t last_written; // last packet send to window
};

struct flow_state_receiver{
    uint16_t next_seq_num_expected; // next packet expected
    uint16_t advertised_window;
    uint16_t last_read;
    uint16_t last_received;
    struct rte_mbuf *window_packets[WINDOW_SIZE];
    uint64_t receive_times[WINDOW_SIZE];
};


#endif //FLOWSTATE_H
