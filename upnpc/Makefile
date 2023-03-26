C := gcc 
A := ar
CFLAGS := -O2 -g -c 

B := ./object/*.o


main: upnpc test_
	#$(A) rcs upnpclib.a $(B)
	$(C) -o upnpc_run $(B)

upnpc:
	$(C) -o ./object/get_gate_way.o $(CFLAGS) ./src/get_gate_way.c
	$(C) -o ./object/mapping.o $(CFLAGS) ./src/mapping.c
	$(C) -o ./object/strnet.o $(CFLAGS) ./src/strnet.c
	$(C) -o ./object/upnpc.o $(CFLAGS) upnpc.c

test_:
	$(C) -o ./object/test.o $(CFLAGS) ./test.c
	
