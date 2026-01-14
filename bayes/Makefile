.PHONY: all switch-p4 ctrl-test ctrl-nb clean

# 默认：只编 P4 + NB controller（不再编 ctrl-test）
all: switch-p4 ctrl-nb

# 如果你还想一次把 test 也编了，用：make switch
switch: switch-p4 ctrl-test ctrl-nb

switch-p4: switch/naive_bayes.p4 switch/header.p4 switch/parser.p4 config.h
	$(SDE_INSTALL)/bin/p4_build.sh $<

ctrl-test: ctrl/test.c
	gcc -I$(SDE_INSTALL)/include -g -O2 -std=gnu11  -L/usr/local/lib -L$(SDE_INSTALL)/lib \
		$< $(SDE_INSTALL)/lib/libboost_system.so.1.67.0 -o contrl_test \
		-ldriver  -lbfutils  -lm -lpthread  -lboost_system \
		-Wl,-rpath=$(SDE_INSTALL)/lib

ctrl-nb: ctrl/naive_bayes_controller.c
	gcc -I$(SDE_INSTALL)/include -g -O2 -std=gnu11 -L$(SDE_INSTALL)/lib \
		$< -o naive_bayes_ctrl \
		-ldriver -lbfutils -lm -lpthread \
		-Wl,-rpath=$(SDE_INSTALL)/lib

clean:
	-rm -f contrl_test naive_bayes_ctrl bf_drivers.log* zlog-cfg-cur
	-rm -rf $(SDE_INSTALL)/share/p4/targets/tofino/naive_bayes.conf
	-rm -rf $(SDE_INSTALL)/share/p4/targets/tofino/naive_bayes
	-rm -rf $(SDE_INSTALL)/lib/naive_bayes.so
	-rm -rf $(SDE_INSTALL)/include/naive_bayes