all: logger acmonitor test_aclog

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lssl -lcrypto -ldl

acmonitor: acmonitor.c
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c
	gcc test_aclog.c -o test_aclog

run: logger.so test_aclog
	sudo touch prive1.txt
	sudo touch prive2.txt
	sudo touch prive3.txt
	sudo touch prive4.txt
	sudo touch prive5.txt
	sudo touch prive6.txt
	sudo touch prive7.txt
	sudo touch prive8.txt
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
