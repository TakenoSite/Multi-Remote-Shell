#include <stdbool.h>

#include "upnpc.h"
#include "src/mapping.h"
#include "src/soap_body.h"
#include "src/get_gate_way.h"


static int config(char *gate_way_ipv4, char *upnp_ipv4, char *upnp_port){
	if(GetGateWayIP(gate_way_ipv4) < 0){
		return -1;
	}

	if(CheckUPnP(gate_way_ipv4, upnp_ipv4, upnp_port) < 0){
		return -2;
	}
	return 0;
}

int GetExternalIPAddress(void)
{
	ROUTER_CONF conf;
	memset(&conf, 0, sizeof(conf));

	int coinfigmation = config(conf.gate_way_ipv4, conf.upnp_ipv4, conf.upnp_port);
	int to_int;
	switch(coinfigmation){
		case 0:
			break;
		default:
			return coinfigmation;
	}
	
	sscanf(conf.upnp_port, "%d", &to_int);
	char *payloads = GetExternalIPAddressBody();
	if(payloads == NULL){
		return -1;
	}

	char *header_create = Header(conf.upnp_ipv4, 
			to_int, strlen(payloads), GET_EXTRERNAL_MODE);
	if(header_create == NULL){
		free(*&payloads);
		return -2;
	}
	

	strcat(header_create, payloads);
	int req = Requests(header_create, conf.upnp_ipv4, to_int);
	
	free(*&payloads);
	free(*&header_create);
	
	switch(req){
		case 200:
			break;
		default:
			return req;
	}
	return 0;	
}


int AddPortMapping(
		UINT16 new_extranl_port,
		UINT16 new_internal_port,
		char* new_internal_client,
		char* new_protocol,
		short lease_duration,
		char* description)
{	
	ROUTER_CONF conf;
	memset(&conf, 0, sizeof(conf));
	int coinfigmation = config(conf.gate_way_ipv4, conf.upnp_ipv4, conf.upnp_port);
	int to_int;
	switch(coinfigmation){
		case 0:
			break;
		default:
			return coinfigmation;
	}
	
	sscanf(conf.upnp_port, "%d", &to_int);
	
	char *payloads = AddPortMappingBody(
			new_extranl_port,
			new_internal_port,
			new_internal_client,
			new_protocol,
			lease_duration,
			description);
	
	if(payloads == NULL){
		return -1;
	}
	
	char *header_create = Header(conf.upnp_ipv4,
			to_int,strlen(payloads), ADD_PORT_MAP_MODE);
	
	if(header_create == NULL){
		free(*&payloads);
		return -2;
	}
	
	strcat(header_create, payloads);
	int req = Requests(header_create, conf.upnp_ipv4, to_int);
	
	free(*&payloads);
	free(*&header_create);
	
	switch(req){
		case 200:
			return 0;

		default:
			return req;
	}

	return 0;
}


int DeletePortMapping(
    UINT16 NEW_EXTRANL_PORT,
    char* NEW_PROTOCOL
	)
{
	ROUTER_CONF conf;
	memset(&conf, 0, sizeof(conf));
	int coinfigmation = config(conf.gate_way_ipv4, conf.upnp_ipv4, conf.upnp_port);
	int to_int;
	switch(coinfigmation){
		case 0:
			break;
		default:
			return coinfigmation;
	}
	
	sscanf(conf.upnp_port, "%d", &to_int);
	
	char *payloads = DeletePortMappingBody(NEW_EXTRANL_PORT, 
			NEW_PROTOCOL);
		
	if(payloads == NULL){
		return -1;
	}

	char *header_create = Header(conf.upnp_ipv4, 
			to_int, strlen(payloads), DELETE_PORT_MAP_MODE);
	
	if(header_create == NULL){
		free(*&payloads);
		return -2;
	}
	
	strcat(header_create, payloads);
	int req = Requests(header_create, conf.upnp_ipv4, to_int);
		
	free(*&payloads);
	free(*&header_create);
	switch(req){
		case 200:
			return 0;

		default:
			return req;
	}

	return 0;
}

int GetGenericPortMappingEntry(void)
{
	ROUTER_CONF conf;
	memset(&conf, 0, sizeof(conf));
	int coinfigmation = config(conf.gate_way_ipv4, 
			conf.upnp_ipv4, conf.upnp_port);
	int to_int;
	int count = 0;
	switch(coinfigmation){
		case 0:
			break;
		default:
			return coinfigmation;
	}
	
	sscanf(conf.upnp_port, "%d", &to_int);

	do{
		char *payloads = GetGenericPortMappingEntryBody(count);
		if(payloads == NULL){
			return -1;
		}
		
		char *header_create = Header(conf.upnp_ipv4, 
				to_int, strlen(payloads), GET_GENERIC_PORT_MAP_ENTRY_MODE);

		if(header_create == NULL){
			free(*&payloads);
			return -2;
		}
		
		strcat(header_create, payloads);
		int req = Requests(header_create, conf.upnp_ipv4, to_int);
		
		free(*&payloads);
		free(*&header_create);
		switch(req){
			case 200:
				count ++;
				break;	
			default:
				return req;
		}

	}while(true);

	return 0;
}

