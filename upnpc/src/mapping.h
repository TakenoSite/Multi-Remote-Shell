#ifndef __MAPPING_H_
#define __MAPPING_H_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

typedef unsigned int UINT;
typedef uint16_t UINT16;
typedef const char C_CHARA;


struct REQUESTS_C{
	struct sockaddr_in addr;	
	char buf[1028];
	int net_status;
	int sockfd;
};


struct HEADER_C{
	char *gate_ware_addressl;
	char *mode;
	UINT16 gate_ware_upnp_port;
	UINT paylaod_lenght;
};

typedef struct HEADER_C HEADER_C;
typedef struct REQUESTS_C REQUESTS_C;

 int Requests(char *payload, char *gate_way_address, UINT16 gate_way_upnp_port);
 char *Header(
                char *gate_way_ip_address,
                UINT16 gate_way_upnp_port,
                int length,
                char *mode
                );
 char *GetExternalIPAddressBody(void);

char *AddPortMappingBody(
		UINT16 new_extranl_port,
		UINT16 new_internal_port,
		char* new_internal_client,
		char* new_protocol,
		short lease_duration,
		char* description);	

 char *DeletePortMappingBody(
                UINT16 NEW_EXTRANL_PORT,
				char* NEW_PROTOCOL);

 char *GetGenericPortMappingEntryBody(
                short count
                );

#endif 
