#ifndef __MAIN_H_
#define __MAIN_H_

#include "src/mapping.h"

struct ROUTER_CONF{
	
	char gate_way_ipv4[16];
	char upnp_ipv4[16];
	char upnp_port[6];
	
};

typedef struct ROUTER_CONF ROUTER_CONF;
int GetExternalIPAddress(void);


int AddPortMapping(
		UINT16 new_extranl_port,
		UINT16 new_internal_port,
		char* new_internal_client,
		char* new_protocol,
		short lease_duration,
		char* description);

int DeletePortMapping(
    UINT16 NEW_EXTRANL_PORT,
    char* NEW_PROTOCOL
	);

int GetGenericPortMappingEntry(void);



#endif 
