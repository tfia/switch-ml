#include <stdio.h>
#include "headers.h"
#include "switch_config.h"
#include "utils.h"
#include <stdlib.h>
#include <inttypes.h>

#include "kmeans_model.h"

typedef enum {
    ACTION_DROP = 0,
    ACTION_FORWARD = 1
} action_type_t;

#define NUM_FEATURES KM_NUM_FEATURES
#define NUM_CLASSES KM_NUM_CLASSES
#define centers km_centers

typedef struct {
    char* feature_table_name;
    uint64_t start, end;
} feature_table_t;

static const feature_table_t feature_tables[NUM_FEATURES] = {
    {"SwitchIngress.ti_f_frame_len", 0, 65535},
    {"SwitchIngress.ti_f_l4_src_port", 0, 65535},
    {"SwitchIngress.ti_f_l4_dst_port", 0, 65535}
};

const char *forward_key_names[NUM_FEATURES] = {
    "ig_md.f_frame_len",
    "ig_md.f_l4_src_port",
    "ig_md.f_l4_dst_port",
};

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

uint64_t calc_dist_sq(int val, int center) {
    int diff = val - center;
    return (uint64_t)((int64_t)diff * diff);
}

/**
 * @brief Programs the feature distance lookup table.
 *
 * @param session       BFRT session handle.
 * @param dev_tgt       Device target.
 * @param table_hdl     Handle of the feature table to program.
 * @param key_field_name Name of the key field (e.g., "ig_md.f_l4_src_port").
 * @param action_name   Name of the action to take (e.g., "SwitchIngress.ai_accumulate_distance").
 * @param feature_idx   Index of the feature (0 to NUM_FEATURES-1)
 * @param range_start   Start of the Key value range to iterate over (inclusive).
 * @param range_end     End of the Key value range to iterate over (inclusive).
 */
void program_feature_table(bf_rt_session_hdl **session,
                           bf_rt_target_t *dev_tgt,
                           bf_rt_table_hdl *table_hdl,
                           const char *key_field_name,
                           const char *action_name,
                           int feature_idx,
                           uint64_t range_start,
                           uint64_t range_end) {
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_id_t key_id, action_id, param_id;

    P4_CHECK(bf_rt_table_key_allocate(table_hdl, &key));
    P4_CHECK(bf_rt_table_data_allocate(table_hdl, &data));

    P4_CHECK(bf_rt_key_field_id_get(table_hdl, key_field_name, &key_id));
    P4_CHECK(bf_rt_action_name_to_id(table_hdl, action_name, &action_id));

    bf_rt_id_t d_ids[NUM_CLASSES]; // Store d1, d2, d3 field IDs
    char param_name[8];
    for (int i = 0; i < NUM_CLASSES; i++) {
        sprintf(param_name, "d%d", i + 1); // d1, d2, d3
        P4_CHECK(bf_rt_data_field_id_with_action_get(table_hdl, param_name, action_id, &d_ids[i]));
    }
    
    for (uint64_t val = range_start; val <= range_end; val++) {
        P4_CHECK(bf_rt_table_key_reset(table_hdl, &key));
        P4_CHECK(bf_rt_key_field_set_value(key, key_id, val));

        // Set action data once per entry, then fill all (d1..d3).
        P4_CHECK(bf_rt_table_action_data_reset(table_hdl, action_id, &data));
        for (int c = 0; c < NUM_CLASSES; c++) {
            uint64_t raw = calc_dist_sq((int)val, centers[c][feature_idx]);
            uint64_t dist = (raw > (uint64_t)715827800) ? (uint64_t)715827800 : raw;
            P4_CHECK(bf_rt_data_field_set_value(data, d_ids[c], dist));
        }

        P4_CHECK(bf_rt_table_entry_add(table_hdl, *session, dev_tgt, key, data));
    }
    
    P4_CHECK(bf_rt_table_key_deallocate(key));
    P4_CHECK(bf_rt_table_data_deallocate(data));
    P4_CHECK(bf_rt_session_complete_operations(*session));
    printf("Programmed feature table for key '%s'\n", key_field_name);
}

/**
 * @brief Programs the min_dist update table.
 *
 * @param session       BFRT session handle.
 * @param dev_tgt       Device target.
 * @param table_hdl     Handle of the feature table to program.
 * @param action_name   Name of the action to take (e.g., "SwitchIngress.ai_update_min_c2"). 
 */
void program_min_update_table(bf_rt_session_hdl **session,
                                bf_rt_target_t *dev_tgt,
                                bf_rt_table_hdl *table_hdl,
                                const char *action_name
                                ) {
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_id_t key_id, action_id;
    P4_CHECK(bf_rt_table_key_allocate(table_hdl, &key));
    P4_CHECK(bf_rt_table_data_allocate(table_hdl, &data));

    P4_CHECK(bf_rt_key_field_id_get(table_hdl, "ig_md.delta_sign", &key_id));
    P4_CHECK(bf_rt_action_name_to_id(table_hdl, action_name, &action_id));

    P4_CHECK(bf_rt_table_key_reset(table_hdl, &key));
    P4_CHECK(bf_rt_key_field_set_value(key, key_id, 1)); // delta_sign == 1
    P4_CHECK(bf_rt_table_action_data_reset(table_hdl, action_id, &data));
    P4_CHECK(bf_rt_table_entry_add(table_hdl, *session, dev_tgt, key, data));

    P4_CHECK(bf_rt_table_key_deallocate(key));
    P4_CHECK(bf_rt_table_data_deallocate(data));
    P4_CHECK(bf_rt_session_complete_operations(*session));
    printf("Programmed feature table for key '%s'\n", "ig_md.delta_sign");
}

/**
 * @brief Programs the forwarding table.
 *
 * @param session       BFRT session handle.
 * @param dev_tgt       Device target.
 * @param table_hdl     Handle of the feature table to program.
 * @param key_field_name Name of the key field (e.g., "ig_md.f_l4_src_port").
 * @param action_name   Name of the action to take (e.g., "SwitchIngress.ai_accumulate_distance").
 * @param egress_port   Egress port to forward packets to.
 */
void program_forward_table(bf_rt_session_hdl **session,
                           bf_rt_target_t *dev_tgt,
                           bf_rt_table_hdl *table_hdl,
                           const char *key_field_name,
                           const char *action_name,
                           uint64_t classification,
                           int egress_port) {
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_id_t key_id, action_id, d_port;

    P4_CHECK(bf_rt_table_key_allocate(table_hdl, &key));
    P4_CHECK(bf_rt_table_data_allocate(table_hdl, &data));

    P4_CHECK(bf_rt_key_field_id_get(table_hdl, key_field_name, &key_id));
    P4_CHECK(bf_rt_action_name_to_id(table_hdl, action_name, &action_id));
    P4_CHECK(bf_rt_data_field_id_with_action_get(table_hdl, "egress_port", action_id, &d_port));

    P4_CHECK(bf_rt_table_key_reset(table_hdl, &key));
    P4_CHECK(bf_rt_key_field_set_value(key, key_id, classification));
    P4_CHECK(bf_rt_table_action_data_reset(table_hdl, action_id, &data));
    P4_CHECK(bf_rt_data_field_set_value(data, d_port, egress_port));
    P4_CHECK(bf_rt_table_entry_add(table_hdl, *session, dev_tgt, key, data));

    P4_CHECK(bf_rt_table_key_deallocate(key));
    P4_CHECK(bf_rt_table_data_deallocate(data));
    P4_CHECK(bf_rt_session_complete_operations(*session));
    printf("Programmed forwarding entry: class=%" PRIu64 " -> egress_port=%d\n",
           classification, egress_port);
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
    const char *P4_PROG_NAME = "kmeans";
    switchd_setup(switchd_ctx, P4_PROG_NAME);
    printf("\nbf_switchd is initialized successfully!\n");

    // Get BfRtInfo and create the bf_runtime session
    bfrt_setup(dev_tgt, &bfrt_info, P4_PROG_NAME, session);
    printf("bfrtInfo is got and session is created successfully!\n");

    // Set up the portable using C bf_pm api, instead of BF_RT CPP
    port_setup(dev_tgt, PORT_LIST, ARRLEN(PORT_LIST));
    printf("$PORT table is set up successfully!\n");

    for (int f_idx = 0; f_idx < NUM_FEATURES; f_idx++) {
        bf_rt_table_hdl *feature_table_hdl;
        P4_CHECK(bf_rt_table_from_name_get(bfrt_info, feature_tables[f_idx].feature_table_name, &feature_table_hdl));

        program_feature_table(session, dev_tgt, feature_table_hdl,
                              forward_key_names[f_idx],
                              "SwitchIngress.ai_accumulate_distance",
                              f_idx,
                              feature_tables[f_idx].start, feature_tables[f_idx].end);
    }

    // Map k-means class label (1..NUM_CLASSES) -> egress port.
    static const int class_to_port[NUM_CLASSES] = {188, 132, 133};
    bf_rt_table_hdl *forward_table_hdl;
    P4_CHECK(bf_rt_table_from_name_get(bfrt_info, "SwitchIngress.ti_forward", &forward_table_hdl));
    for (int cls = 0; cls < NUM_CLASSES; cls++) {
        program_forward_table(session, dev_tgt, forward_table_hdl,
                              "ig_md.classification",
                              "SwitchIngress.ai_forward",
                              (uint64_t)(cls + 1),
                              class_to_port[cls]);
    }

    bf_rt_table_hdl *min_update_table_hdl;
    P4_CHECK(bf_rt_table_from_name_get(bfrt_info, "SwitchIngress.ti_update_min_c2", &min_update_table_hdl));
    program_min_update_table(session, dev_tgt, min_update_table_hdl,
                             "SwitchIngress.ai_update_min_c2");

    P4_CHECK(bf_rt_table_from_name_get(bfrt_info, "SwitchIngress.ti_update_min_c3", &min_update_table_hdl));
    program_min_update_table(session, dev_tgt, min_update_table_hdl,
                             "SwitchIngress.ai_update_min_c3");

    printf("All table entries are added successfully!\n");
    printf("Setup is completed successfully! Entering infinite loop...\n");
    while(1);
    return 0;
}