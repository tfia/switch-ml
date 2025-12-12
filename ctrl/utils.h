#include "headers.h"

#define P4_CHECK(call) do { \
	bf_status_t bf_status = call; \
	if (bf_status != BF_SUCCESS) { \
		fprintf(stderr, "P4 Error at %s:%d: %s\n", __FILE__, __LINE__, bf_err_str(bf_status)); \
		exit(EXIT_FAILURE); \
	} \
} while (0)

static void mac_str_to_bytes(const char *mac_str, uint8_t out[6]) {
    unsigned int b[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) == 6) {
        for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
    } else {
        memset(out, 0, 6);
        printf("Error parsing MAC string: %s\n", mac_str);
    }
}