#ifndef _HEADERS_H
#define _HEADERS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <bf_rt/bf_rt_init.h>
#include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_table_key.h>
#include <bf_rt/bf_rt_table_data.h>
#include <bf_rt/bf_rt_table.h>
#include <bf_rt/bf_rt_session.h>
#include <bf_switchd/bf_switchd.h>
#include <tofino/pdfixed/pd_conn_mgr.h>
#include <tofino/pdfixed/pd_mirror.h>
#include <bf_pm/bf_pm_intf.h>
#include <mc_mgr/mc_mgr_intf.h>
#include <tofino/bf_pal/bf_pal_port_intf.h>
#include <traffic_mgr/traffic_mgr_types.h>
#include <traffic_mgr/traffic_mgr_ppg_intf.h>
#include <traffic_mgr/traffic_mgr_port_intf.h>
#include <traffic_mgr/traffic_mgr_q_intf.h>

// for channel
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
#include <unistd.h>
// #include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <sys/socket.h>
// #include <cstddef> 
#include <stdlib.h>
// #include <time.h>

#include "../config.h"

#define ARRLEN(arr) sizeof(arr) / sizeof(arr[0])
#if __TOFINO_MODE__ == 0
const char *P4_PROG_NAME = "simple_acl";
// static const char CPUIF_NAME[] = "bf_pci0";
static const char CPUIF_NAME[] = "enp4s0f0";
#else
const char *P4_PROG_NAME = "forward";
// static const char CPUIF_NAME[] = "veth251";//?
#endif

typedef struct switch_port_s
{
    char fp_port[32];
} switch_port_t;

typedef struct switch_s
{
    bf_rt_target_t dev_tgt;
    bf_rt_session_hdl *session;

} switch_t;

typedef struct ti_get_port_info_entry_s
{
    // Key value
    bf_dev_port_t egress_port;
    // Action
    char action[16];
    // Data value
    const char *port_ip;
    const char *port_mac;
} ti_get_port_info_entry_t;

typedef struct ti_get_port_info_info_s
{
    // Key field ids
    bf_rt_id_t kid_egress_port;
    // Action Ids
    bf_rt_id_t aid_ai_get_port_info;
    bf_rt_id_t aid_ai_drop;
    // Data field Ids for ai_get_port_info
    bf_rt_id_t did_port_ip;
    bf_rt_id_t did_port_mac;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_table_hdl *table;
} ti_get_port_info_info_t;

typedef struct ti_ipv4_lpm_entry_s
{
    // Key value
    const char *dst_ip;
    // Match length (for LPM)
    uint16_t match_length;
    // Action
    char action[16];
    // Data value
    bf_dev_port_t egress_port;
} ti_ipv4_lpm_entry_t;

typedef struct ti_ipv4_acl_lpm_entry_s
{
    // Key value
    const char *src_ip;
    // Match length (for LPM)
    uint16_t match_length;
    // Action
    char action[16];
} ti_ipv4_acl_lpm_entry_t;

typedef struct ti_ipv4_lpm_info_s
{
    // Key field ids
    bf_rt_id_t kid_dst_ip;
    // Action Ids
    bf_rt_id_t aid_ai_ipv4_forward;
    bf_rt_id_t aid_ai_drop;
    // Data field Ids for ipv4_forward
    bf_rt_id_t did_egress_port;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_table_hdl *table;
} ti_ipv4_lpm_info_t;

typedef struct ti_ipv4_acl_lpm_info_s
{
    // Key field ids
    bf_rt_id_t kid_src_ip;
    // Action Ids
    bf_rt_id_t aid_ai_no_action;
    bf_rt_id_t aid_ai_drop;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_table_hdl *table;
} ti_ipv4_acl_lpm_info_t;

typedef struct
{
    uint8_t addr[6];
} ethaddr;

typedef struct ti_set_dst_mac_entry_s
{
    // Key value
    uint32_t dst_ip;
    // Action
    char action[16];
    // Data value
    uint64_t dst_mac;
} ti_set_dst_mac_entry_t;

typedef struct ti_set_dst_mac_info_s
{
    // Key field ids
    bf_rt_id_t kid_dst_ip;
    // Action Ids
    bf_rt_id_t aid_ai_set_dst_mac;
    bf_rt_id_t aid_ai_arp_request;
    // Data field Ids for ai_set_dst_mac
    bf_rt_id_t did_dst_mac;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    bf_rt_table_hdl *table;
} ti_set_dst_mac_info_t;

// ---------Channel ---------------

typedef struct
{
    // uint8_t type;
    ethaddr mac;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed)) upload_h;

typedef struct p4_channel_s
{
    int sockfd;
    char recvbuf[PKTBUF_SIZE];
} p4_channel_t;

int create_p4_channel(p4_channel_t *channel);
int process_packet_from_p4(p4_channel_t *channel, upload_h *upload);

#endif
