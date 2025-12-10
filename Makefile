.PHONY: switch switch-p4 switch-ctrl ctrl clean 


switch: switch-p4 ctrl

switch-p4: switch/switch.p4 switch/header.p4 switch/parser.p4 config.h
	$(SDE_INSTALL)/bin/p4_build.sh $<


ctrl: ctrl/test.c
	gcc -I$$SDE_INSTALL/include -g -O2 -std=gnu11  -L/usr/local/lib -L$$SDE_INSTALL/lib \
		$< $(SDE_INSTALL)/lib/libboost_system.so.1.67.0 -o control \
		-ldriver  -lbfutils  -lm -lpthread  -lboost_system\
		-Wl,-rpath=$$SDE_INSTALL/lib

clean:
	-rm -f contrl bf_drivers.log* zlog-cfg-cur
