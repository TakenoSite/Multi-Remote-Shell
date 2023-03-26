#include "strnet.h"

static int char_int(char* str_){
        int to_int;
        if(sscanf(str_,"%d",&to_int) == 0){
			return -1;
		}
        return to_int;
}

int StatusCheck(char* r){
        short int_status_code;
        char* r_cpy = (char*)malloc(sizeof(char) * strlen(r)+32);
        
		if(r_cpy == NULL){
                return -1;
        };

        sprintf(r_cpy,"%s",r);

        char *ptr = strtok(r_cpy, "\r\n");
        char *status_code = strtok(ptr, " ");
        
		status_code = strtok(NULL, " ");
        int_status_code = char_int(status_code);
		if(int_status_code < 0){
			return -1;
		}
		
        free(r_cpy);

        return int_status_code;
}


int HeaderSplit_to_Url(char* body, char* name, char* resolve){
        char* r_cpy = (char*)malloc(sizeof(char) * strlen(body));
        char* check;
        sprintf(r_cpy, "%s", body);
        char *ptr = strtok(r_cpy, "\r\n");
        while(ptr != NULL){
                ptr = strtok(NULL, "\r\n");
                if(ptr != NULL && strstr(ptr, name) != NULL){
                        check = strstr(ptr, name);
                        if(check == NULL) return -1;
                        sprintf(resolve, "%s", check);
                        free(r_cpy);
                        break;
                }
        }
        return 0;
}
