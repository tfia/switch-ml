.PHONY: switch switch-dt switch-km ctrl clean


switch: switch-dt switch-km ctrl

switch-dt: switch/decision_tree.p4 switch/header.p4 switch/parser.p4 config.h
	$(SDE_INSTALL)/bin/p4_build.sh $<

switch-km: switch/kmeans.p4 switch/header.p4 switch/parser.p4 config.h
	$(SDE_INSTALL)/bin/p4_build.sh $<

ctrl: ctrl/decision_tree.c
	gcc -I$$SDE_INSTALL/include -g -O2 -std=gnu11  -L/usr/local/lib -L$$SDE_INSTALL/lib \
		$< $(SDE_INSTALL)/lib/libboost_system.so.1.67.0 -o decision_tree \
		-ldriver  -lbfutils  -lm -lpthread  -lboost_system\
		-Wl,-rpath=$$SDE_INSTALL/lib

clean:
	-rm -f contrl bf_drivers.log* zlog-cfg-cur decision_tree
