FROM debian:buster-slim

RUN apt-get update -y; apt-get install build-essential python3 -y
ADD flag-encryptor.c /flag-encryptor.c
ADD enc.py /enc.py
ADD flag_backup.png /flag.png
COPY ./tiny-AES-c /tiny-AES-c
ADD Makefile /Makefile
RUN make all
