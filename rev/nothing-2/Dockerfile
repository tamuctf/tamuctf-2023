FROM debian:buster-slim

RUN apt-get update -y; apt-get install build-essential -y
ADD nothing-2.c /nothing-2.c
ADD Makefile /Makefile
RUN make all

