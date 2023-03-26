#include <stdio.h>
#include <netdb.h>
#include <string.h>
#define IPV4_BUF 16

char Ipv4[IPV4_BUF];
char *IPAddressResolve(char *srchost)
{
	
	struct hostent *hostent;
	if((hostent = gethostbyname(srchost)) == NULL) return NULL;
	sprintf(Ipv4, "%u.%u.%u.%u",
			(unsigned char)hostent -> h_addr_list[0][0],
			(unsigned char)hostent -> h_addr_list[0][1],
			(unsigned char)hostent -> h_addr_list[0][2],
			(unsigned char)hostent -> h_addr_list[0][3]);
	return Ipv4;
};

