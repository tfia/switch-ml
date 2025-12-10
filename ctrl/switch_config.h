#ifndef _SWITCH_CONFIG_H
#define _SWITCH_CONFIG_H

#if __TOFINO_MODE__ == 0
const switch_port_t PORT_LIST[] = {
        {"9/0"}, {"9/1"}, {"9/2"}, {"9/3"}
};

const ti_ipv4_lpm_entry_t IPV4_LPM_LIST[] = {
    {"192.168.1.0", 24, "ai_ipv4_forward", 132},
    {"192.168.2.0", 24, "ai_ipv4_forward", 133},
};

const ti_get_port_info_entry_t GET_PORT_INFO_LIST[] = {
    {132, "ai_get_port_info", "192.168.1.1", "8C:1F:64:69:1F:01"},
    {133, "ai_get_port_info", "192.168.2.1", "8C:1F:64:69:1F:02"},
};


#else
const switch_port_t  PORT_LIST[] = {
    {"1/0"}, {"2/0"}, {"3/0"}, 
    {"4/0"}, {"5/0"}, {"6/0"}, // {"7/0"}, {"8/0"}, // pipe of mode
};

#endif

#endif