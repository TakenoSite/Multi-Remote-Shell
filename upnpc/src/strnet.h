#ifndef __STRNET_H_
#define __STRNET_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int StatusCheck(char* r);
int HeaderSplit_to_Url(char* body, char* name, char* resolve);

#endif 
