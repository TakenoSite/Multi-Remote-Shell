#include "get_gate_way.h"
#include "soap_body.h"
#include "strnet.h"

int GetGateWayIP(char* resolve)
{
    int     received_bytes = 0, msg_len = 0, route_attribute_len = 0;
    int     sock = -1;
	unsigned int msgseq = 0;
    struct  nlmsghdr *nlh, *nlmsg;
    struct  rtmsg *route_entry;
    struct  rtattr *route_attribute;
    char    gateway_address[INET_ADDRSTRLEN], interface[IF_NAMESIZE];
    char    msgbuf[BUFFER_SIZE], buffer[BUFFER_SIZE];
    char    *ptr = buffer;
    struct timeval tv;

    if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
        return -1;
    }

    memset(msgbuf, 0, sizeof(msgbuf));
    memset(gateway_address, 0, sizeof(gateway_address));
    memset(interface, 0, sizeof(interface));
    memset(buffer, 0, sizeof(buffer));

    nlmsg = (struct nlmsghdr *)msgbuf;
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = RTM_GETROUTE;
    nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlmsg->nlmsg_seq = msgseq++;
    nlmsg->nlmsg_pid = getpid();
    tv.tv_sec = 1;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, 
			(struct timeval *)&tv, sizeof(struct timeval));
	
    if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
		close(sock);
        return -2;
    }
    do
    {
        received_bytes = recv(sock, ptr, sizeof(buffer) - msg_len, 0);
        if (received_bytes < 0) {
			close(sock);
            return -3;
        }

        nlh = (struct nlmsghdr *) ptr;

        if((NLMSG_OK(nlmsg, received_bytes) == 0) ||
           (nlmsg->nlmsg_type == NLMSG_ERROR))
        {
			close(sock);
            return -4;
        }

        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        else {
            ptr += received_bytes;
            msg_len += received_bytes;
        }

        if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
            break;
	}

    while ((nlmsg->nlmsg_seq != msgseq) || (nlmsg->nlmsg_pid != getpid()));

    for ( ; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes))
    {
        route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

        if (route_entry->rtm_table != RT_TABLE_MAIN)
            continue;

        route_attribute = (struct rtattr *) RTM_RTA(route_entry);
        route_attribute_len = RTM_PAYLOAD(nlh);

        for ( ; RTA_OK(route_attribute, route_attribute_len);
              route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
        {
            switch(route_attribute->rta_type) {
            case RTA_OIF:
                if_indextoname(*(int *)RTA_DATA(route_attribute), interface);
                break;
            case RTA_GATEWAY:
                inet_ntop(AF_INET, RTA_DATA(route_attribute),
                          gateway_address, sizeof(gateway_address));
                break;
            default:
                break;
            }
        }

        if ((*gateway_address) && (*interface)) {
                        sprintf(resolve,"%s", gateway_address);
            break;
        }
    }
    close(sock);
    return 0;
}


int CheckUPnP(char* gate_way_ipv4, char* resolve_host, char* resolve_port){
	char upnp_protocol_url[MESSAGE_BUFFOR];

	GetGateWayIP(gate_way_ipv4);
	struct sockaddr_in ssdp;
    char message[MESSAGE_BUFFOR];
	char buffer[RESPONSE_BUFFOR];
	int sock_ssdp;
	int UPnPPort[] = {1900, 3000}; 
	char *host;
	char *port;

	struct timeval tv;
	fd_set readfds;
	int timecount;
	
	sock_ssdp = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock_ssdp < 0){
		return -1;
	}
	
	int i=0;
	for(; i < 2; i++){
			memset(message, 0, sizeof(message));
			memset(buffer, 0, sizeof(buffer));

            sprintf(message, GET_UPNP_REQUEST_SOAP,
				gate_way_ipv4, UPnPPort[i]);

			ssdp.sin_addr.s_addr = inet_addr(gate_way_ipv4);
			ssdp.sin_family = AF_INET;
			ssdp.sin_port = htons(UPnPPort[i]);
			sendto(sock_ssdp, message, sizeof(message), 0, 
					(struct sockaddr *)&ssdp, sizeof(ssdp));
			
			tv.tv_sec = 2;
			tv.tv_usec = 0;
			FD_ZERO(&readfds);
			FD_SET(sock_ssdp, &readfds);
			timecount = select(sock_ssdp + 1, &readfds, NULL, NULL, &tv);

			if(timecount != 0){
					recv(sock_ssdp, buffer, sizeof(buffer), 0);
					if(HeaderSplit_to_Url(buffer, "http://", upnp_protocol_url) < 0){
						close(sock_ssdp);
						return -2;
					}
					
					char *ptr = strtok(upnp_protocol_url, "/");
					ptr = strtok(NULL, "/");
					host = strtok(ptr, ":");
					port = strtok(NULL, ":");

					break;
			};
        }

	if(timecount != 0){
			sprintf(resolve_host, "%s", host);
			sprintf(resolve_port, "%s", port);
			close(sock_ssdp);
			return 0;
	}else{
			close(sock_ssdp);
			return -1;
	}

}
