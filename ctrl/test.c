#include <stdio.h>
#include "headers.h"
#include "switch_config.h"
#include "utils.h"
#include <stdlib.h>


typedef enum {
    ACTION_DROP = 0,
    ACTION_FORWARD = 1
} action_type_t;

// For "when...then..." decision rules
// -1 for Don't Care
typedef struct {
    int f1_id_start; int f1_id_end; // ID range
    int f2_id_start; int f2_id_end;
    int f3_id_start; int f3_id_end;
    action_type_t type;
    int egress_port; // Dismiss if type == ACTION_DROP
    uint8_t dst_mac[6];
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
    bf_rt_id_t k_f1, k_f2, k_f3;
    bf_rt_id_t a_fwd, a_drop;
    bf_rt_id_t d_dst_mac, d_port;

    P4_CHECK(bf_rt_table_key_allocate(table_hdl, &key));
    P4_CHECK(bf_rt_table_data_allocate(table_hdl, &data));

    // Get IDs
    P4_CHECK(bf_rt_key_field_id_get(table_hdl, "ig_md.action_select_1", &k_f1));
    P4_CHECK(bf_rt_key_field_id_get(table_hdl, "ig_md.action_select_2", &k_f2));
    P4_CHECK(bf_rt_key_field_id_get(table_hdl, "ig_md.action_select_3", &k_f3));
    
    P4_CHECK(bf_rt_action_name_to_id(table_hdl, "SwitchIngress.ai_ipv4_forward", &a_fwd));
    P4_CHECK(bf_rt_action_name_to_id(table_hdl, "SwitchIngress.ai_drop", &a_drop));
    
    P4_CHECK(bf_rt_data_field_id_with_action_get(table_hdl, "dst_mac", a_fwd, &d_dst_mac));
    P4_CHECK(bf_rt_data_field_id_with_action_get(table_hdl, "egress_port", a_fwd, &d_port)); 

    for(int r = 0; r < num_rules; r++) {
        decision_rule_t rule = rules[r];
        
        for (int i = rule.f1_id_start; i <= rule.f1_id_end; i++) {
            for (int j = rule.f2_id_start; j <= rule.f2_id_end; j++) {
                for (int k = rule.f3_id_start; k <= rule.f3_id_end; k++) {
                    
                    P4_CHECK(bf_rt_table_key_reset(table_hdl, &key));
                    P4_CHECK(bf_rt_key_field_set_value(key, k_f1, i));
                    P4_CHECK(bf_rt_key_field_set_value(key, k_f2, j));
                    P4_CHECK(bf_rt_key_field_set_value(key, k_f3, k));

                    if (rule.type == ACTION_DROP) {
                        P4_CHECK(bf_rt_table_action_data_reset(table_hdl, a_drop, &data));
                    } else {
                        P4_CHECK(bf_rt_table_action_data_reset(table_hdl, a_fwd, &data));
                        P4_CHECK(bf_rt_data_field_set_value(data, d_port, rule.egress_port));
                        P4_CHECK(bf_rt_data_field_set_value_ptr(data, d_dst_mac, rule.dst_mac, 6));
                    }

                    P4_CHECK(bf_rt_table_entry_add(table_hdl, *session, dev_tgt, key, data));
                }
            }
        }
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
    const char *P4_PROG_NAME = "switch";
    switchd_setup(switchd_ctx, P4_PROG_NAME);
    printf("\nbf_switchd is initialized successfully!\n");

    // Get BfRtInfo and create the bf_runtime session
    bfrt_setup(dev_tgt, &bfrt_info, P4_PROG_NAME, session);
    printf("bfrtInfo is got and session is created successfully!\n");

    // Set up the portable using C bf_pm api, instead of BF_RT CPP
    port_setup(dev_tgt, PORT_LIST, ARRLEN(PORT_LIST));
    printf("$PORT table is set up successfully!\n");

    // Key field ids
    bf_rt_id_t kid_ingress_port;

    // Action Ids
    bf_rt_id_t aid_ai_forward;
    bf_rt_id_t aid_ai_drop;
    bf_rt_id_t aid_ai_ipv4_forward;
    bf_rt_id_t aid_ai_select_1;
    bf_rt_id_t aid_ai_select_2;
    bf_rt_id_t aid_ai_select_3;

    // Data field Ids for forward
    bf_rt_id_t did_egress_port;

    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_table_hdl *ti_feature_1_hdl, *ti_feature_2_hdl, *ti_feature_3_hdl, *ti_ipv4_forward_hdl;

    // Get table objects from name
    P4_CHECK(bf_rt_table_from_name_get(bfrt_info, "SwitchIngress.ti_feature_1", &ti_feature_1_hdl));
    P4_CHECK(bf_rt_table_from_name_get(bfrt_info, "SwitchIngress.ti_feature_2", &ti_feature_2_hdl));
    P4_CHECK(bf_rt_table_from_name_get(bfrt_info, "SwitchIngress.ti_feature_3", &ti_feature_3_hdl));
    P4_CHECK(bf_rt_table_from_name_get(bfrt_info, "SwitchIngress.ti_ipv4_forward", &ti_ipv4_forward_hdl));
    printf("All table handles obtained successfully!\n");

    // Program featurees
    // proto = []
    // src = [11, 22157, 23505, 43174, 49930]
    // dst = [6039, 9144, 22157]
    
    // Feature 1: Proto 
    uint64_t thres_proto[] = {0, 32};
    program_feature_table(session, dev_tgt, ti_feature_1_hdl, 
                          "hdr.ipv4.protocol", "SwitchIngress.ai_select_1", "feature_val_1", 
                          thres_proto, 2);

    // Feature 2: Src
    uint64_t thres_src[] = {0, 11, 22157, 23505, 43174, 49930, 65535};
    program_feature_table(session, dev_tgt, ti_feature_2_hdl, 
                          "hdr.tcp.src_port", "SwitchIngress.ai_select_2", "feature_val_2", 
                          thres_src, 7);

    // Feature 3: Dst
    uint64_t thres_dst[] = {0, 6039, 9144, 22157, 65535};
    program_feature_table(session, dev_tgt, ti_feature_3_hdl, 
                          "hdr.tcp.dst_port", "SwitchIngress.ai_select_3", "feature_val_3", 
                          thres_dst, 5);

    // Program forwarding rules
    
    #define MAX_F1 1
    #define MAX_F2 6
    #define MAX_F3 4

    uint8_t default_mac[6] = {0x8C, 0x1F, 0x64, 0x69, 0x1F, 0x01};

    #define EGRESS_PORT_2 133
    #define EGRESS_PORT_3 134

    decision_rule_t rules[] = {
        // Rule 1: when src<=11.0 then 2
        // Tree: 2 -> Map: Class 2 is [3] -> Port 3
        { .f1_id_start=0, .f1_id_end=MAX_F1, 
          .f2_id_start=0, .f2_id_end=0,
          .f3_id_start=0, .f3_id_end=MAX_F3, 
          .type=ACTION_FORWARD, .egress_port=EGRESS_PORT_3, 
          .dst_mac={0x8C, 0x1F, 0x64, 0x69, 0x1F, 0x01} },

        // Rule 2: when src>11.0 and dst<=6039.0 and src<=23505.5 then 0
        // Tree: 0 -> Map: Class 0 is [3] -> Port 3
        { .f1_id_start=0, .f1_id_end=MAX_F1,
          .f2_id_start=1, .f2_id_end=2,
          .f3_id_start=0, .f3_id_end=0,
          .type=ACTION_FORWARD, .egress_port=EGRESS_PORT_3,
          .dst_mac={0x8C, 0x1F, 0x64, 0x69, 0x1F, 0x01} },

        // Rule 3: when src>11.0 and dst<=6039.0 and src>23505.5 and src<=49930.0 then 4
        // Tree: 4 -> Map: Class 4 is [2] -> Port 2
        { .f1_id_start=0, .f1_id_end=MAX_F1,
          .f2_id_start=3, .f2_id_end=4,
          .f3_id_start=0, .f3_id_end=0,
          .type=ACTION_FORWARD, .egress_port=EGRESS_PORT_2,
          .dst_mac={0x8C, 0x1F, 0x64, 0x69, 0x1F, 0x01} },

        // Rule 4: when src>11.0 and dst<=6039.0 and src>23505.5 and src>49930.0 then 3
        // Tree: 3 -> Map: Class 3 is [3] -> Port 3
        { .f1_id_start=0, .f1_id_end=MAX_F1,
          .f2_id_start=5, .f2_id_end=5,
          .f3_id_start=0, .f3_id_end=0,
          .type=ACTION_FORWARD, .egress_port=EGRESS_PORT_3,
          .dst_mac={0x8C, 0x1F, 0x64, 0x69, 0x1F, 0x01} },

        // Rule 5: when src>11 and dst>6039 and src<=43174.5 and dst<=22157.5 and dst<=9144.0 then 4
        // Tree: 4 -> Map: Class 4 is [2] -> Port 2
        { .f1_id_start=0, .f1_id_end=MAX_F1,
          .f2_id_start=1, .f2_id_end=3,
          .f3_id_start=1, .f3_id_end=1,
          .type=ACTION_FORWARD, .egress_port=EGRESS_PORT_2,
          .dst_mac={0x8C, 0x1F, 0x64, 0x69, 0x1F, 0x01} },

        // Rule 6: when src>11 and dst>6039 and src<=43174.5 and dst<=22157.5 and dst>9144.0 then 1
        // Tree: 1 -> Map: Class 1 is [3] -> Port 3
        { .f1_id_start=0, .f1_id_end=MAX_F1,
          .f2_id_start=1, .f2_id_end=3,
          .f3_id_start=2, .f3_id_end=2,
          .type=ACTION_FORWARD, .egress_port=EGRESS_PORT_3,
          .dst_mac={0x8C, 0x1F, 0x64, 0x69, 0x1F, 0x01} },

        // Rule 7: when src>11 and dst>6039 and src<=43174.5 and dst>22157.5 and src<=22157.5 then 1
        // Tree: 1 -> Map: Class 1 is [3] -> Port 3
        { .f1_id_start=0, .f1_id_end=MAX_F1,
          .f2_id_start=1, .f2_id_end=1,
          .f3_id_start=3, .f3_id_end=3,
          .type=ACTION_FORWARD, .egress_port=EGRESS_PORT_3,
          .dst_mac={0x8C, 0x1F, 0x64, 0x69, 0x1F, 0x01} },

        // Rule 8: when src>11 and dst>6039 and src<=43174.5 and dst>22157.5 and src>22157.5 then 3
        // Tree: 3 -> Map: Class 3 is [3] -> Port 3
        { .f1_id_start=0, .f1_id_end=MAX_F1,
          .f2_id_start=2, .f2_id_end=3,
          .f3_id_start=3, .f3_id_end=3,
          .type=ACTION_FORWARD, .egress_port=EGRESS_PORT_3,
          .dst_mac={0x8C, 0x1F, 0x64, 0x69, 0x1F, 0x01} },

        // Rule 9: when src>11 and dst>6039 and src>43174.5 then 4
        // Tree: 4 -> Map: Class 4 is [2] -> Port 2
        { .f1_id_start=0, .f1_id_end=MAX_F1,
          .f2_id_start=4, .f2_id_end=5,
          .f3_id_start=1, .f3_id_end=3,
          .type=ACTION_FORWARD, .egress_port=EGRESS_PORT_2,
          .dst_mac={0x8C, 0x1F, 0x64, 0x69, 0x1F, 0x01} },
    };

    program_forward_rules(
        session, dev_tgt, 
        ti_ipv4_forward_hdl, 
        rules, 
        sizeof(rules) / sizeof(rules[0])
    );

    printf("All table entries are added successfully!\n");
    printf("Setup is completed successfully! Entering infinite loop...\n");
    while(1);
    return 0;
}