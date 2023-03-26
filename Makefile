c = ~/Downloads/armv5l/cross-compiler-armv5l_2/bin/armv5l-gcc
#c = gcc 
CFLAGS := -O2 -g -c 
PRODUCT_NAME := p2p_door_gate

lib := upnp_lib network_lib core
object_file := ./object/*.o

main:$(lib)	
	$(c) $(object_file) -o $(PRODUCT_NAME) -lpthread

core:
	$(c) -Wall -Wextra -O2 -lpthread -DTEST  -c x41.c -o ./object/x41.o

upnp_lib:
	$(c) -o ./object/get_gate_way.o $(CFLAGS) ./upnpc/src/get_gate_way.c
	$(c) -o ./object/mapping.o $(CFLAGS) ./upnpc/src/mapping.c
	$(c) -o ./object/strnet.o $(CFLAGS) ./upnpc/src/strnet.c
	$(c) -o ./object/upnpc.o $(CFLAGS) ./upnpc/upnpc.c

network_lib:
	$(c) -o ./object/getlocalhost.o $(CFLAGS) ./network/getlocalhost.c
	$(c) -o ./object/ip_address_resolut.o $(CFLAGS) ./network/ip_address_resolut.c
