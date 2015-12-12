CXX?=c++

all: snmp_proxy

snmp_proxy: snmp_proxy.h snmp_proxy.cpp snmp_proxy_main.cpp Makefile
	${CXX} -std=c++11 -W -Wall -lpthread -lboost_program_options \
	-lboost_system -I/usr/local/include -L/usr/local/lib \
	snmp_proxy.cpp snmp_proxy_main.cpp -o snmp_proxy

clean:
	rm snmp_proxy
