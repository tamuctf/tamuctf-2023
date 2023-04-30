FROM debian:buster-slim as build

ARG name
ARG lib

RUN apt-get update -y; apt-get install build-essential -y
ADD $name.c /tmp/$name.c
ADD $lib.c /tmp/$lib.c
ADD $lib.h /tmp/$lib.h
ADD Makefile /tmp/Makefile
RUN cd /tmp/; make all

FROM debian:buster-slim

ARG name
ARG port

RUN apt-get update -y; apt-get install socat -y
COPY --from=build /tmp/$name /pwn/$name
COPY --from=build /tmp/lib$name.so /pwn/lib$name.so
COPY flag.txt /pwn/flag.txt
WORKDIR /pwn

EXPOSE $port

RUN echo "exec socat -s TCP-LISTEN:$port,reuseaddr,fork EXEC:/pwn/$name,stderr" > /pwn/docker_entrypoint.sh

ENTRYPOINT ["sh", "/pwn/docker_entrypoint.sh"]


