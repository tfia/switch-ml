#include <stdio.h>
#include "headers.h"
#include "switch_config.h"
#include "utils.h"
#include <stdlib.h>

#define NUM_FEATURES 11

typedef enum {
    ACTION_DROP = 0,
    ACTION_FORWARD = 1
} action_type_t;

typedef struct {
    int f_id_start[NUM_FEATURES];
    int f_id_end[NUM_FEATURES];
    action_type_t type;
    int egress_port;
} decision_rule_t;


static void port_setup(const bf_rt_target_t *dev_tgt,
                       const switch_port_t *port_list,
                       const uint8_t port_count)
{
    bf_status_t bf_status;

    // Add and enable ports
    for (unsigned int idx = 0; idx < port_count; idx++)
    {
        bf_pal_front_port_handle_t port_hdl;
        bf_status = bf_pm_port_str_to_hdl_get(dev_tgt->dev_id,
                                              port_list[idx].fp_port,
                                              &port_hdl);
        assert(bf_status == BF_SUCCESS);
        bf_status = bf_pm_port_add(dev_tgt->dev_id, &port_hdl,
                                   BF_SPEED_10G, BF_FEC_TYP_NONE);
        assert(bf_status == BF_SUCCESS);
        bf_status = bf_pm_port_enable(dev_tgt->dev_id, &port_hdl);
        assert(bf_status == BF_SUCCESS);
        printf("Port %s is enabled successfully!\n", port_list[idx].fp_port);
    }
}

static void switchd_setup(bf_switchd_context_t *switchd_ctx, const char *prog)
{
    char conf_file[256];
    char bf_sysfs_fname[128] = "/sys/class/bf/bf0/device";
    FILE *fd;

    switchd_ctx->install_dir = strdup(getenv("SDE_INSTALL"));
    sprintf(conf_file, "%s%s%s%s",
            getenv("SDE_INSTALL"), "/share/p4/targets/tofino/", prog, ".conf");
    switchd_ctx->conf_file = conf_file;
    switchd_ctx->running_in_background = 1;
    switchd_ctx->dev_sts_thread = 1;
    switchd_ctx->dev_sts_port = 7777; // 9090?

    //    switchd_ctx->kernel_pkt = true;
    // Determine if kernel mode packet driver is loaded
    strncat(bf_sysfs_fname, "/dev_add",
            sizeof(bf_sysfs_fname) - 1 - strlen(bf_sysfs_fname));
    printf("bf_sysfs_fname %s\n", bf_sysfs_fname);
    fd = fopen(bf_sysfs_fname, "r");
    if (fd != 0)
    {
        // override previous parsing if bf_kpkt KLM was loaded
        printf("kernel mode packet driver present, forcing kpkt option!\n");
        switchd_ctx->kernel_pkt = 1;
        fclose(fd);
    }

    assert(bf_switchd_lib_init(switchd_ctx) == BF_SUCCESS);
    printf("\nbf_switchd is initialized correctly!\n");
}

static void bfrt_setup(const bf_rt_target_t *dev_tgt,
                       const bf_rt_info_hdl **bfrt_info,
                       const char *prog,
                       bf_rt_session_hdl **session)
{

    bf_status_t bf_status;

    // Get bfrtInfo object from dev_id and p4 program name
    bf_status = bf_rt_info_get(dev_tgt->dev_id, prog, bfrt_info);
    assert(bf_status == BF_SUCCESS);
    // Create a session object
    bf_status = bf_rt_session_create(session);
    assert(bf_status == BF_SUCCESS);
    printf("bfrt_info is got and session is created correctly!\n");
    //	return bf_status;
}

int create_p4_channel(p4_channel_t *channel)
{
    struct ifreq cpuif_req;
    struct sockaddr_ll sock_addr;
    int sock_addrlen = sizeof(sock_addr);
    char cpuif_name[IFNAMSIZ];

    /* Get interface name */
    strcpy(cpuif_name, CPUIF_NAME);

    channel->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    /* Open RAW socket to send on */
    if (channel->sockfd == -1)
    {
        perror("socket");
        return -1;
    }

    memset(&cpuif_req, 0, sizeof(struct ifreq));
    strncpy(cpuif_req.ifr_name, cpuif_name, IFNAMSIZ - 1);
    ioctl(channel->sockfd, SIOCGIFFLAGS, &cpuif_req);
    cpuif_req.ifr_flags |= IFF_PROMISC;
    ioctl(channel->sockfd, SIOCSIFFLAGS, &cpuif_req);

    if (setsockopt(channel->sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                   cpuif_name, IFNAMSIZ - 1) == -1)
    {
        perror("SO_BINDTODEVICE");
        close(channel->sockfd);
        return -1;
    }

    /* Construct the Ethernet header */
    memset(channel->recvbuf, 0, PKTBUF_SIZE);

    return 0;
}

/**
 * @brief Programs the feature discretization table (e.g., ti_feature_1, ti_feature_2).
 *
 * @param session       BFRT session handle.
 * @param dev_tgt       Device target.
 * @param table_hdl     Handle of the feature table to program.
 * @param key_field_name Name of the key field (e.g., "hdr.tcp.src_port").
 * @param action_name   Name of the action to take (e.g., "SwitchIngress.ai_select_2").
 * @param param_name    Name of the action parameter (e.g., "feature_val_2").
 * @param thresholds    Array of threshold values that define the ranges.
 * @param num_thresholds Number of thresholds in the array.
 */
void program_feature_table(bf_rt_session_hdl **session,
                           bf_rt_target_t *dev_tgt,
                           bf_rt_table_hdl *table_hdl,
                           const char *key_field_name,
                           const char *action_name,
                           const char *param_name,
                           const uint64_t thresholds[],
                           int num_thresholds) {
    bf_status_t bf_status;
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_id_t key_id, action_id, param_id;

    P4_CHECK(bf_rt_table_key_allocate(table_hdl, &key));
    P4_CHECK(bf_rt_table_data_allocate(table_hdl, &data));

    P4_CHECK(bf_rt_key_field_id_get(table_hdl, key_field_name, &key_id));
    P4_CHECK(bf_rt_action_name_to_id(table_hdl, action_name, &action_id));
    P4_CHECK(bf_rt_data_field_id_with_action_get(table_hdl, param_name, action_id, &param_id));

    uint64_t low_bound = 0;
    // For each threshold, create a range and program an entry
    for (int i = 0; i < num_thresholds; i++) {
        uint64_t high_bound = thresholds[i];
        if (low_bound > high_bound) continue;

        P4_CHECK(bf_rt_table_key_reset(table_hdl, &key));
        P4_CHECK(bf_rt_key_field_set_value_range(key, key_id, low_bound, high_bound));

        // Discretized feature value is the index of the threshold
        P4_CHECK(bf_rt_table_action_data_reset(table_hdl, action_id, &data));
        P4_CHECK(bf_rt_data_field_set_value(data, param_id, i)); // Use index (ID) as feature value

        P4_CHECK(bf_rt_table_entry_add(table_hdl, *session, dev_tgt, key, data));
        low_bound = high_bound + 1;
    }
    
    P4_CHECK(bf_rt_table_key_deallocate(key));
    P4_CHECK(bf_rt_table_data_deallocate(data));
    P4_CHECK(bf_rt_session_complete_operations(*session));
    printf("Programmed feature table for key '%s'\n", key_field_name);
}

const char *forward_key_names[NUM_FEATURES] = {
    "ig_md.action_select_packet_len",
    "ig_md.action_select_ether_type",
    "ig_md.action_select_ipv4_proto",
    "ig_md.action_select_ipv4_flags",
    "ig_md.action_select_ipv6_next_hdr",
    "ig_md.action_select_ipv6_options",
    "ig_md.action_select_tcp_src_port",
    "ig_md.action_select_tcp_dst_port",
    "ig_md.action_select_tcp_flags",
    "ig_md.action_select_udp_src_port",
    "ig_md.action_select_udp_dst_port"
};

/**
 * @brief Programs the forwarding decision table based on provided rules.
 *
 * @param session       BFRT session handle.
 * @param dev_tgt       Device target.
 * @param table_hdl     Handle of the feature table to program.
 * @param rules         Array of decision rules.
 * @param num_rules     Number of rules in the array.
 */
void program_forward_rules(bf_rt_session_hdl **session,
                           bf_rt_target_t *dev_tgt,
                           bf_rt_table_hdl *table_hdl,
                           decision_rule_t *rules,
                           int num_rules) {
    
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_id_t key_ids[NUM_FEATURES];
    bf_rt_id_t a_fwd, a_drop;
    bf_rt_id_t d_port;

    P4_CHECK(bf_rt_table_key_allocate(table_hdl, &key));
    P4_CHECK(bf_rt_table_data_allocate(table_hdl, &data));

    // Get Key IDs
    for(int i = 0; i < NUM_FEATURES; i++) {
        P4_CHECK(bf_rt_key_field_id_get(table_hdl, forward_key_names[i], &key_ids[i]));
    }
    
    P4_CHECK(bf_rt_action_name_to_id(table_hdl, "SwitchIngress.ai_forward", &a_fwd));
    P4_CHECK(bf_rt_action_name_to_id(table_hdl, "SwitchIngress.ai_drop", &a_drop));
    
    P4_CHECK(bf_rt_data_field_id_with_action_get(table_hdl, "egress_port", a_fwd, &d_port)); 

    for(int r = 0; r < num_rules; r++) {
        decision_rule_t rule = rules[r];
        
        P4_CHECK(bf_rt_table_key_reset(table_hdl, &key));

        // Set ranges for all 11 features
        for(int i = 0; i < NUM_FEATURES; i++) {
            P4_CHECK(bf_rt_key_field_set_value_range(key, key_ids[i], rule.f_id_start[i], rule.f_id_end[i]));
        }

        if (rule.type == ACTION_DROP) {
            P4_CHECK(bf_rt_table_action_data_reset(table_hdl, a_drop, &data));
        } else {
            P4_CHECK(bf_rt_table_action_data_reset(table_hdl, a_fwd, &data));
            P4_CHECK(bf_rt_data_field_set_value(data, d_port, rule.egress_port));
        }

        P4_CHECK(bf_rt_table_entry_add(table_hdl, *session, dev_tgt, key, data));
    }
    
    P4_CHECK(bf_rt_table_key_deallocate(key));
    P4_CHECK(bf_rt_table_data_deallocate(data));
    P4_CHECK(bf_rt_session_complete_operations(*session));
    printf("Programmed forwarding rules successfully.\n");
}

int main()
{
    printf("Hello, World!\n");
    switch_t iswitch;
    bf_switchd_context_t *switchd_ctx;
    bf_rt_target_t *dev_tgt = &iswitch.dev_tgt;
    const bf_rt_info_hdl *bfrt_info = 0;
    bf_rt_session_hdl **session = &iswitch.session;

    dev_tgt->dev_id = 0;
    dev_tgt->pipe_id = BF_DEV_PIPE_ALL;

    // Initialize and set the bf_switchd
    switchd_ctx = (bf_switchd_context_t *)
        calloc(1, sizeof(bf_switchd_context_t));
    if (switchd_ctx == 0)
    {
        printf("Cannot allocate switchd context\n");
        return -1;
    }
    const char *P4_PROG_NAME = "decision_tree";
    switchd_setup(switchd_ctx, P4_PROG_NAME);
    printf("\nbf_switchd is initialized successfully!\n");

    // Get BfRtInfo and create the bf_runtime session
    bfrt_setup(dev_tgt, &bfrt_info, P4_PROG_NAME, session);
    printf("bfrtInfo is got and session is created successfully!\n");

    // Set up the portable using C bf_pm api, instead of BF_RT CPP
    port_setup(dev_tgt, PORT_LIST, ARRLEN(PORT_LIST));
    printf("$PORT table is set up successfully!\n");

    // Program Features
    // Define thresholds for testing
    uint64_t thres_pkt_len[] = {64, 128, 256, 512, 1024, 1518};
    uint64_t thres_ether_type[] = {0x0800, 0x0806, 0x86DD};
    uint64_t thres_ipv4_proto[] = {1, 6, 17};
    uint64_t thres_ipv4_flags[] = {0, 1, 2};
    uint64_t thres_ipv6_next_hdr[] = {6, 17, 58};
    uint64_t thres_ipv6_options[] = {0, 43, 44, 50, 51, 60};
    uint64_t thres_tcp_src[] = {80, 443, 8080};
    uint64_t thres_tcp_dst[] = {80, 443, 8080};
    uint64_t thres_tcp_flags[] = {0x02, 0x10, 0x18}; // SYN, ACK, PSH+ACK
    uint64_t thres_udp_src[] = {53, 123};
    uint64_t thres_udp_dst[] = {53, 123};

    struct {
        const char *table; const char *key; const char *action; const char *param;
        uint64_t *thres; int num;
    } features[] = {
        {"SwitchIngress.ti_packet_len", "ig_md.ip_len", "SwitchIngress.ai_select_packet_len", "val", thres_pkt_len, 6},
        {"SwitchIngress.ti_ether_type", "hdr.ethernet.ether_type", "SwitchIngress.ai_select_ether_type", "val", thres_ether_type, 3},
        {"SwitchIngress.ti_ipv4_proto", "hdr.ipv4.protocol", "SwitchIngress.ai_select_ipv4_proto", "val", thres_ipv4_proto, 3},
        {"SwitchIngress.ti_ipv4_flags", "hdr.ipv4.flags", "SwitchIngress.ai_select_ipv4_flags", "val", thres_ipv4_flags, 3},
        {"SwitchIngress.ti_ipv6_next_hdr", "hdr.ipv6.next_hdr", "SwitchIngress.ai_select_ipv6_next_hdr", "val", thres_ipv6_next_hdr, 3},
        {"SwitchIngress.ti_ipv6_options", "hdr.ipv6.next_hdr", "SwitchIngress.ai_select_ipv6_options", "val", thres_ipv6_options, 6},
        {"SwitchIngress.ti_tcp_src_port", "hdr.tcp.src_port", "SwitchIngress.ai_select_tcp_src_port", "val", thres_tcp_src, 3},
        {"SwitchIngress.ti_tcp_dst_port", "hdr.tcp.dst_port", "SwitchIngress.ai_select_tcp_dst_port", "val", thres_tcp_dst, 3},
        {"SwitchIngress.ti_tcp_flags", "hdr.tcp.flags", "SwitchIngress.ai_select_tcp_flags", "val", thres_tcp_flags, 3},
        {"SwitchIngress.ti_udp_src_port", "hdr.udp.src_port", "SwitchIngress.ai_select_udp_src_port", "val", thres_udp_src, 2},
        {"SwitchIngress.ti_udp_dst_port", "hdr.udp.dst_port", "SwitchIngress.ai_select_udp_dst_port", "val", thres_udp_dst, 2},
    };

    for (int i = 0; i < 11; i++) {
        bf_rt_table_hdl *table_hdl;
        P4_CHECK(bf_rt_table_from_name_get(bfrt_info, features[i].table, &table_hdl));
        program_feature_table(session, dev_tgt, table_hdl, 
                              features[i].key, features[i].action, features[i].param, 
                              features[i].thres, features[i].num);
    }

    // Program Forwarding Rules
    bf_rt_table_hdl *ti_forward_hdl;
    P4_CHECK(bf_rt_table_from_name_get(bfrt_info, "SwitchIngress.ti_forward", &ti_forward_hdl));

    #define EGRESS_PORT 188

    // Create 1 catch-all rule to forward everything to EGRESS_PORT
    decision_rule_t rules[1];
    
    // Rule 1: Match ALL -> Port 188
    for(int i = 0; i < NUM_FEATURES; i++) { 
        rules[0].f_id_start[i] = 0; 
        rules[0].f_id_end[i] = 0xFFF; 
    }
    rules[0].type = ACTION_FORWARD;
    rules[0].egress_port = EGRESS_PORT;

    program_forward_rules(session, dev_tgt, ti_forward_hdl, rules, 1);

    printf("All table entries are added successfully!\n");
    printf("Setup is completed successfully! Entering infinite loop...\n");
    while(1);
    return 0;
}