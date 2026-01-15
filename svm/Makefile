.PHONY: all switch-p4 ctrl-test ctrl-nb clean

# 默认：只编 P4 + NB controller（不再编 ctrl-test）
all: switch-p4 ctrl-nb

# 如果你还想一次把 test 也编了，用：make switch
switch: switch-p4 ctrl-test ctrl-nb

switch-p4: switch/svm.p4 switch/header.p4 switch/parser.p4 config.h
	$(SDE_INSTALL)/bin/p4_build.sh $<

ctrl-test: ctrl/test.c
	gcc -I$(SDE_INSTALL)/include -g -O2 -std=gnu11  -L/usr/local/lib -L$(SDE_INSTALL)/lib \
		$< $(SDE_INSTALL)/lib/libboost_system.so.1.67.0 -o contrl_test \
		-ldriver  -lbfutils  -lm -lpthread  -lboost_system \
		-Wl,-rpath=$(SDE_INSTALL)/lib

ctrl-nb: ctrl/svm_controller.c
	gcc -I$(SDE_INSTALL)/include -g -O2 -std=gnu11 -L$(SDE_INSTALL)/lib \
		$< -o svm_ctrl \
		-ldriver -lbfutils -lm -lpthread \
		-Wl,-rpath=$(SDE_INSTALL)/lib

clean:
	-rm -f contrl_test svm_ctrl bf_drivers.log* zlog-cfg-cur
	-rm -rf $(SDE_INSTALL)/share/p4/targets/tofino/svm.conf
	-rm -rf $(SDE_INSTALL)/share/p4/targets/tofino/svm
	-rm -rf $(SDE_INSTALL)/lib/svm.so
	-rm -rf $(SDE_INSTALL)/include/svm