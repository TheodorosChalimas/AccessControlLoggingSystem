## Code in C programming language that utilizes an access control logging system tool in C. The access control logging system monitors and keeps track of every file access and modification that occurs in the system.

Folder contains:
* logger.c
"Contains the C code used for utilizing the fopen() and fwrite() functions to be preloaded, which in turn call the original fopen() and fwrite() respectivelly. The new functions log the file accesses in a file_loffing.log file."

* acmonitor.c 
"Contains the C code used for monitoring the users file accesses and classifiying the results acording to the operation requested(Use comand ./acmonitor -h for tool usage)."

* test_aclog.c
"Contains the C code used for testing the tool. More specifically generates 10 files which are accesible by the user and writes to them their respective names and then tries to open 8 private files which are sudo generated in the makefile, with no access permision."

* Makefile
"make all <--Compile c files."
"make run <--Create 8 private files as (Password requested), preload the logger.so to the test_aclog.o and run it(file_logging.log should be created)."
	

<thodorischa@gmail.com>

