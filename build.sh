#!/bin/bash
CFLAGS="-g -Wall -DOPENSSL_NO_ENGINE"
LIBS="-lcrypto -lssl -lpam"
gcc server.c -o server.o $CFLAGS $LIBS
