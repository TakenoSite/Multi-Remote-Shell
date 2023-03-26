#ifndef _GETGATEWAY_H_
#define _GETGATEWAY_H_
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>

#define BUFFER_SIZE 4096
#define RESPONSE_BUFFOR 1024
#define IPV4_BUFFOR     32
#define MESSAGE_BUFFOR 196


int GetGateWayIP(char* resolve);
int CheckUPnP(char* gate_way_ipv4, char* resolve_host, char* resolve_port);

#endif
