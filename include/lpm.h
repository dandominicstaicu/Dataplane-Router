#ifndef _LPM_H_
#define _LPM_H_

#include "lib.h"
#include "protocols.h"

struct route_table_entry *lpm(uint32_t ip_dest);

#endif