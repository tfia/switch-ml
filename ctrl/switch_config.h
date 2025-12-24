#ifndef _SWITCH_CONFIG_H
#define _SWITCH_CONFIG_H

#if __TOFINO_MODE__ == 0
const switch_port_t PORT_LIST[] = {
        {"9/0"}, {"9/1"}, {"9/2"}, {"9/3"}, {"11/0"}, {"13/0"}
};

#else
const switch_port_t  PORT_LIST[] = {
    {"1/0"}, {"2/0"}, {"3/0"}, 
    {"4/0"}, {"5/0"}, {"6/0"}, // {"7/0"}, {"8/0"}, // pipe of mode
};

#endif

#endif