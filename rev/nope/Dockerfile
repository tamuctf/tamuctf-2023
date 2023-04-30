FROM ubuntu:22.04

RUN apt-get update -y; apt-get install build-essential -y
ADD nope.c /nope.c
ADD Makefile /Makefile
RUN make all
