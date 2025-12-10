#include <stdio.h>
#include "headers.h"
#include "switch_config.h"
#include <stdlib.h>
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

void print_upload_h(upload_h *upload)
{
    printf("upload_h:\n");
    // printf("type: %d\n", upload->type);
    uint32_t src_ip = ntohl(upload->src_ip);
    uint32_t dst_ip = ntohl(upload->dst_ip);
    printf("mac: %02x:%02x:%02x:%02x:%02x:%02x\n", upload->mac.addr[0], upload->mac.addr[1], upload->mac.addr[2], upload->mac.addr[3], upload->mac.addr[4], upload->mac.addr[5]);
    printf("src_ip: %d.%d.%d.%d\n", (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF);
    printf("dst_ip: %d.%d.%d.%d\n", (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF);
}

int process_packet_from_p4(p4_channel_t *channel, upload_h *upload)
{
    int rx_len = 0;

    /* Header structures */
    rx_len = recvfrom(channel->sockfd, channel->recvbuf,
                      PKTBUF_SIZE, 0, 0, 0);
    if (rx_len < 0)
    {
        printf("Recv failed\n");
        return -1;
    }

    if (rx_len == 0)
    {
        // printf("Recv zero\n");
        return 0;
    }

    struct ethhdr *eth_h = (struct ethhdr *)channel->recvbuf;

    if (ntohs(eth_h->h_proto) == ETHER_TYPE_UPLOAD)
    { // check polling header
        memcpy(upload, (upload_h *)((char *)eth_h + sizeof(struct ethhdr)), sizeof(upload_h));
        return rx_len - sizeof(struct ethhdr);
    } else {
        // printf("Received non-uploading packet, proto: 0x%04x\n", ntohs(eth_h->h_proto));
        return 0;
    }
    return 0;
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

int main()
{
    printf("Hello, World!\n");
    bf_status_t bf_status;
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
    const char *P4_PROG_NAME = "simple_forward";
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
    // Data field Ids for forward
    bf_rt_id_t did_egress_port;

    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_table_hdl *table;

    // Get table object from name
    printf("Get table object from name\n");
    bf_status = bf_rt_table_from_name_get(bfrt_info,
                                          "SwitchIngress.ti_forward",
                                          &table);

    assert(bf_status == BF_SUCCESS);
    printf("Get table object from name successfully!\n");

    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(table, &key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(table, &data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field
    bf_status = bf_rt_key_field_id_get(table, "ig_intr_md.ingress_port",
                                       &kid_ingress_port);
    assert(bf_status == BF_SUCCESS);
    // Get action Ids for action forward
    bf_status = bf_rt_action_name_to_id(table, "SwitchIngress.ai_forward",
                                        &aid_ai_forward);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_action_name_to_id(table, "SwitchIngress.ai_drop",
                                        &aid_ai_drop);
    assert(bf_status == BF_SUCCESS);
    // Get field-ids for data field
    bf_status = bf_rt_data_field_id_with_action_get(
        table, "egress_port",
        aid_ai_forward,
        &did_egress_port);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(*session);
    assert(bf_status == BF_SUCCESS);
    printf("Table ti_forward is init correctly!\n");

    // Add entries into the table

    // Reset key before use
    bf_rt_table_key_reset(table, &key);
    // Fill in the Key object
    bf_status = bf_rt_key_field_set_value(key, kid_ingress_port, 132);
    assert(bf_status == BF_SUCCESS);
    // Reset data before use
    bf_rt_table_action_data_reset(table, aid_ai_forward, &data);
    // Fill in the Data object
    bf_status = bf_rt_data_field_set_value(data, did_egress_port, 133);
    assert(bf_status == BF_SUCCESS);
    // Call table entry add API
    bf_status = bf_rt_table_entry_add(table, *session, dev_tgt,
                                        key,
                                        data);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(*session);
    assert(bf_status == BF_SUCCESS);
    printf("Add ti_forward entry successfully!\n");

    // Reset key before use
    bf_rt_table_key_reset(table, &key);
    // Fill in the Key object
    bf_status = bf_rt_key_field_set_value(key, kid_ingress_port, 133);
    assert(bf_status == BF_SUCCESS);
    // Reset data before use
    bf_rt_table_action_data_reset(table, aid_ai_forward, &data);
    // Fill in the Data object
    bf_status = bf_rt_data_field_set_value(data, did_egress_port, 132);
    assert(bf_status == BF_SUCCESS);
    // Call table entry add API
    bf_status = bf_rt_table_entry_add(table, *session, dev_tgt,
                                        key,
                                        data);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(*session);
    assert(bf_status == BF_SUCCESS);
    printf("Add ti_forward entry successfully!\n");

    // while(1);

    // set up CPU-Dataplane channel
    p4_channel_t channel;
    int status;
    status = create_p4_channel(&channel);
    if (status == 0)
    {
        printf("upload channel created\n");
    }
    upload_h upload;
    // Set up the portable using C bf_pm api, instead of BF_RT CPP
    while (1)
    {

        // Receive packet
        status = process_packet_from_p4(&channel, &upload);
        if (status > 0)
        {
            printf("Debug: Recv uploading\n");
            print_upload_h(&upload);
        }
    }
    return 0;
}