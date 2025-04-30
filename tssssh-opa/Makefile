.PHONY: all

all: client server

build_dir:
	mkdir -p build/

server: build_dir include/aes.h src/aes.c src/test_server/server.c
	gcc -o build/test_server -I./include ./src/aes.c ./src/test_server/server.c

client: build_dir include/aes.h src/aes.c src/client/client.c
	gcc -o build/client -I./include ./src/aes.c ./src/client/client.c
