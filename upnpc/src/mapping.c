#include "soap_body.h"
#include "mapping.h"
#include "strnet.h"

/*
typedef const char C_CHARA;
 int StringCpy(char dst[], int len, C_CHARA *body, C_CHARA *fmt, ...){
	
	va_list ap;
	va_start(ap, fmt);
	int res = snprintf(dst, len, body, fmt);
	if(res > len){
		return -1;
	}
	va_end(ap);
	return 0;
}
*/

 int Requests(char *payload, char *gate_way_address, UINT16 gate_way_upnp_port){
	REQUESTS_C Req;
	memset(&Req, 0, sizeof(Req));
		
	Req.sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(Req.sockfd < 0){
		printf("sock : %d\n", errno);
		return -1;
	}

	Req.addr.sin_addr.s_addr = inet_addr(gate_way_address);
	Req.addr.sin_port = htons(gate_way_upnp_port);
	Req.addr.sin_family = AF_INET;
	
	if(connect(Req.sockfd, (struct sockaddr *)&Req.addr, sizeof(Req.addr)) < 0){
		printf("connect : %d\n", errno);
		return -1;
	};
	
	if(send(Req.sockfd, payload, strlen(payload), 0) < 0){
		printf("send : %d\n", errno);
		return -1;
	}
	
	recv(Req.sockfd, Req.buf, sizeof(Req.buf), 0);
	//puts(Req.buf);
	Req.net_status = StatusCheck(Req.buf);
	if(Req.net_status < 0){
		return -2;
	}

	
	close(Req.sockfd);
	return Req.net_status;
}


// Body Generate 
 char *Header(
		char *gate_way_ip_address,
		UINT16 gate_way_upnp_port,
		int length,
		char *mode
		)
{
	size_t paylaod_lenght = HEADER_BODY_SIZE + length + 1;
	char *buf = (char*)malloc(paylaod_lenght);
	if(buf == NULL){
		return NULL;
	}

	size_t len = snprintf(buf, HEADER_BODY_SIZE-1, 
			HEADER, gate_way_ip_address, gate_way_upnp_port, length, mode);	
	
	if(len > paylaod_lenght){
		free(buf);
		return NULL;
	}
	return buf;
}


 char *GetExternalIPAddressBody(void)
{
	char *buf = (char*)malloc(GET_EXTRERNAL_SIZE);

	if(buf == NULL){
		return NULL;
	}
	
	size_t len  = snprintf(buf, GET_EXTRERNAL_SIZE-1, "%s", GET_EXTRERNAL_SOAP);
	if(len > GET_EXTRERNAL_SIZE){
		free(buf);
		return NULL;
	}

	return buf;
}


 char *AddPortMappingBody(
		UINT16 new_extranl_port,
		UINT16 new_internal_port,
		char* new_internal_client,
		char* new_protocol,
		short lease_duration,
		char* description)	
{
	char *buf = (char*)malloc(ADD_PORT_MAP_SIZE);
	if(buf == NULL){
		return NULL;
	}

	size_t len = snprintf(buf, ADD_PORT_MAP_SIZE-1, 
			ADD_PORT_MAPPING_SOAP, 
			new_extranl_port,
			new_protocol,
			new_internal_port,
			new_internal_client,
			description,
			lease_duration);

	if(len > ADD_PORT_MAP_SIZE){
		free(buf);
		return NULL;
	}
			
	return buf;
}


 char *DeletePortMappingBody(
		UINT16 NEW_EXTRANL_PORT,
        char* NEW_PROTOCOL)
{
	char *buf = (char*)malloc(DELETE_PORT_MAP_SIZE);
	if(buf == NULL){
		return NULL;
	}
	
	size_t len = snprintf(buf, DELETE_PORT_MAP_SIZE, DELETE_PORT_MAPPING_SOAP,
			NEW_EXTRANL_PORT, NEW_PROTOCOL);

	if(DELETE_PORT_MAP_SIZE < len){
		free(buf);
		return NULL;
	}

	return buf;
}


 char *GetGenericPortMappingEntryBody(
		short count
		)
{
	char *buf = (char*)malloc(GET_GENERIC_PORT_MAP_ENTRY_SIZE);
	if(buf == NULL){
		return NULL;
	}

	size_t len = snprintf(buf, GET_GENERIC_PORT_MAP_ENTRY_SIZE 
			,GET_GENERIC_PORT_MAPPING_ENTRY_SOAP, count);

	if(GET_GENERIC_PORT_MAP_ENTRY_SIZE < len){
		free(buf);
		return NULL;
	}

	return buf;
}


// end
