#Linux Generic
CC=gcc

#uncomment next line to compile with musl, suitable for statical compile
#CC=musl-gcc
#CC=/opt/cross/bin/arm-linux-musleabihf-gcc

OUTPATH=./build/
SOURCE_MODULES_PATH=./library/

#FOR DEBUG PURPOSE
#CFLAGSTEMP=-c -Wall -I. -g -O0

ENDFLAG=
#uncomment next line to compile static no libc required, 
#ENDFLAG=-static

#FOR RELEASE
CFLAGSTEMP=-c -Wall -Wno-unused-variable -Wno-unused-but-set-variable -I.

OPTIMIZATION=-O3
HEADERS=-I
LIBPATH=./build/modules/
BUILDFILES=start uFTP end
LIBS=-lpthread

ENABLE_LARGE_FILE_SUPPORT=
#TO ENABLE THE LARGE FILE SUPPORT UNCOMMENT THE NEXT LINE
ENABLE_LARGE_FILE_SUPPORT=-D LARGE_FILE_SUPPORT_ENABLED -D _LARGEFILE64_SOURCE

ENABLE_OPENSSL_SUPPORT=
#TO ENABLE OPENSSL SUPPORT UNCOMMENT NEXT 2 LINES
ENABLE_OPENSSL_SUPPORT=-D OPENSSL_ENABLED
LIBS=-lpthread -lssl -lcrypto


ENABLE_IPV6_SUPPORT=
#TO ENABLE IPV6 support uncomment next line
ENABLE_IPV6_SUPPORT=-D IPV6_ENABLED

ENABLE_PAM_SUPPORT=
PAM_AUTH_LIB=
#TO ENABLE PAM AUTH UNCOMMENT NEXT TWO LINES
#ENABLE_PAM_SUPPORT= -D PAM_SUPPORT_ENABLED
#PAM_AUTH_LIB= -lpam

CFLAGS=$(CFLAGSTEMP) $(ENABLE_LARGE_FILE_SUPPORT) $(ENABLE_OPENSSL_SUPPORT) $(ENABLE_IPV6_SUPPORT) $(ENABLE_PAM_SUPPORT)

all: $(BUILDFILES)

start:
	@echo Compiler: $(CC)
	@echo Output Directory: $(OUTPATH)
	@echo CGI FILES: $(BUILDFILES)
	@rm -rf $(LIBPATH)*.o $(OUTPATH)uFTP
	@echo "Clean ok"

end:
	@echo Build process end

uFTP: uFTP.c fileManagement.o configRead.o logFunctions.o ftpCommandElaborate.o ftpData.o ftpServer.o daemon.o signals.o connection.o openSsl.o dynamicMemory.o errorHandling.o auth.o log.o
	@$(CC)  $(ENABLE_LARGE_FILE_SUPPORT) $(ENABLE_OPENSSL_SUPPORT) uFTP.c $(LIBPATH)dynamicVectors.o $(LIBPATH)fileManagement.o $(LIBPATH)configRead.o $(LIBPATH)logFunctions.o $(LIBPATH)ftpCommandElaborate.o $(LIBPATH)ftpData.o $(LIBPATH)ftpServer.o $(LIBPATH)daemon.o $(LIBPATH)signals.o $(LIBPATH)connection.o $(LIBPATH)openSsl.o $(LIBPATH)dynamicMemory.o $(LIBPATH)errorHandling.o $(LIBPATH)auth.o $(LIBPATH)log.o -o $(OUTPATH)uFTP $(LIBS) $(PAM_AUTH_LIB) $(ENDFLAG)

daemon.o:
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)daemon.c -o $(LIBPATH)daemon.o

dynamicVectors.o:
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)dynamicVectors.c -o $(LIBPATH)dynamicVectors.o

openSsl.o:
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)openSsl.c -o $(LIBPATH)openSsl.o

auth.o:
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)auth.c -o $(LIBPATH)auth.o

configRead.o: dynamicVectors.o fileManagement.o
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)configRead.c -o $(LIBPATH)configRead.o

dynamicMemory.o:
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)dynamicMemory.c -o $(LIBPATH)dynamicMemory.o

errorHandling.o:
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)errorHandling.c -o $(LIBPATH)errorHandling.o

fileManagement.o:
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)fileManagement.c -o $(LIBPATH)fileManagement.o

signals.o:
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)signals.c -o $(LIBPATH)signals.o

connection.o: log.o
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)connection.c -o $(LIBPATH)connection.o

log.o:
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)log.c -o $(LIBPATH)log.o

logFunctions.o:
	@$(CC) $(CFLAGS) $(SOURCE_MODULES_PATH)logFunctions.c -o $(LIBPATH)logFunctions.o

ftpCommandElaborate.o:
	@$(CC) $(CFLAGS) ftpCommandElaborate.c -o $(LIBPATH)ftpCommandElaborate.o

ftpData.o:
	@$(CC) $(CFLAGS) ftpData.c -o $(LIBPATH)ftpData.o

ftpServer.o: openSsl.o
	@$(CC) $(CFLAGS) ftpServer.c -o $(LIBPATH)ftpServer.o

clean:
	@rm -rf $(LIBPATH)*.o $(OUTPATH)uFTP
	@echo "Clean ok"
