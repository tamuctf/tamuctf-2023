FROM debian:buster-slim

RUN apt-get update -y; apt-get install build-essential -y
ADD nothing.c /nothing.c
ADD Makefile /Makefile
RUN make all
