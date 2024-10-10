#include <stdio.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_errno.h>

#include <rte_flow.h>

#include <rte_flow.h>

int check_rte_flow_support(uint16_t port_id) {
    struct rte_flow_error error;
    struct rte_flow_attr attr = {0};
    struct rte_flow_item pattern[] = {
        {
            .type = RTE_FLOW_ITEM_TYPE_END
        }
    };
    struct rte_flow_action action[] = {
        {
            .type = RTE_FLOW_ACTION_TYPE_END
        }
    };

    int ret = rte_flow_validate(port_id, &attr, pattern, action, &error);

    if (ret != 0) {
        if (ret == -ENOTSUP) {
            printf("Port %u does not support rte_flow\n", port_id);
        } else {
            printf("Error validating flow: %s\n", error.message);
        }
        return 0;
    }

    printf("Port %u supports rte_flow\n", port_id);
    return 1;
}
int main(int argc, char *argv[]) {
    int ret;
    uint16_t port_id;

    // Initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    // Check the number of available ports
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
    }

    printf("Number of Ethernet ports available: %d\n", nb_ports);

    // Check MT lock-free support for each available port
   check_rte_flow_support(1);

    // Clean up EAL
    rte_eal_cleanup();

    return 0;
}