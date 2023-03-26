#ifndef __X41_H_
#define __X41_H_

#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>

#include "upnpc/upnpc.h"
#include "network/getlocalhost.h"
#include "network/ip_address_resolut.h"

#define BASE64_BUF 64
#define MESSAGE_BUF 1024
#define DSTHOST_BUF 32
#define DSTPORT_BUF 6
#define SETUSER_BUF 32
#define FILENAME_BUF 128
#define RELAY_SERVER_RES_BUF 64
#define RELAY_BIND_BOOL_BUF 16

#define BIND_PORT0_REQUEST "PEJJTkQ+PE5PREVfVFlQRT5QT1JUMDwvTk9ERV9UWVBFPjwvQklORD4="
#define RELAY_SERVER_UPDATE_CODE "PFVQREFURT48L1VQREFURT4="

#define RELAY_SERVER_UPDATE_TIME 5


struct DOOR_SESISON{
	char buf[MESSAGE_BUF];		// for raw data
	char valus[MESSAGE_BUF];	// for decode data
	char *decode_body;          // 
	char set_pass[SETUSER_BUF];	// confirmation buffer in password
	char set_user[SETUSER_BUF];	// confirmation buffer in username
	char host[DSTHOST_BUF];		// dst host in buffer
	char port[DSTPORT_BUF];		// dst port in buffer
	char filename[FILENAME_BUF];// for upload unit's filename buffer
	short port_s;				// dst_char_port to dst_short_port
};

static int decode_base64_to_6bit(int c);
static char *decode_base64(char *src);
static int tag_format_parse(char* body, char* name, char* resolve, size_t buf_size);
static int door(char *rhost, int rport);
static void door_session(bool nat_type);
static bool nat_config(void);
static void *relay_session_update();
static int GetUdpDstPort(int sock);
static int SockTimeout(int sockfd,int sec, int usec);
static int upload(char *rhost, int rport, char *filename);

#endif
