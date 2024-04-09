#include "lpm.h"

/* Routing table */
extern struct route_table_entry rtable[800000];
extern int rtable_len;


struct route_table_entry *lpm(uint32_t ip_dest) {
    struct route_table_entry *best_match = NULL;
    int left = 0, right = rtable_len - 1;
    
    while (left <= right) {
        int mid = (left + right) / 2;
        uint32_t prefix_match = rtable[mid].prefix & rtable[mid].mask;
        uint32_t destination_prefix = ip_dest & rtable[mid].mask;

        if (destination_prefix == prefix_match) {
            if (!best_match || rtable[mid].mask > best_match->mask) {
                best_match = &rtable[mid];
                // Shift search right to find longest match
                left = mid + 1;
            } else {
                // If current mask is not longer, continue searching right
                left = mid + 1;
            }
        } else if (destination_prefix < prefix_match) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    return best_match;
}
