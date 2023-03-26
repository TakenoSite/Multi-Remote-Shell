#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

char* GetLocalIPAddress(void)
{
	struct sockaddr_in addr, res_addr;
	memset(&addr, 0, sizeof(addr));
	memset(&res_addr, 0, sizeof(res_addr));
	
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s < 0){
		return NULL;
	}

	// 1.2.3.4 is dammy address
	addr.sin_addr.s_addr =  inet_addr("1.2.3.4");
	addr.sin_family = AF_INET;
	
	if(connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0){
		close(s);
		return NULL;	
	}

	socklen_t len = sizeof(res_addr);
	int status = getsockname(s, (struct sockaddr *)&res_addr, &len);
	if(status >= 0){
		close(s);
		return inet_ntoa(res_addr.sin_addr);
	}
	close(s);
	return NULL;
}
