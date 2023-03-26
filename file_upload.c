#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int uplaod(char *rhost, int rport, char *filename) {

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return -1;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(rport);
  addr.sin_addr.s_addr = inet_addr(rhost);
  if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	  perror("connect error");
    return -2;
  }

  FILE *fp = fopen(filename, "rb");
  if (fp == NULL) {
    perror("fopen");
    return -3;
  }

  char buf[1024];
  ssize_t len;
  while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
    if (send(sockfd, buf, len, 0) < 0) {
      perror("send");
      break;
    }
  }

  puts("[*] completed");
  fclose(fp);
  close(sockfd);
  
  return 0;
}


int main(int argc, char* argv[]){
	
	
	char *host = argv[1];
	int port;
	char *filename = argv[3];

	if(!sscanf(argv[2], "%d", &port))
		return -1;
	
	uplaod(host, port, filename);
	return 0;
}
