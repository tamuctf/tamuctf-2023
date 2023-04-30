FROM rust:slim-buster as build

COPY server/ /opt/server/
RUN cd /opt/server && cargo build --release

FROM debian:buster-slim as build2
RUN apt-get update -y && apt-get install build-essential -y
ARG name

COPY $name.c /tmp/$name.c
COPY Makefile /tmp/Makefile
RUN cd /tmp/; make

FROM debian:buster-slim

ARG name
ARG port
ENV PORT=$port
ENV NAME=$name

COPY flag.txt /flag.txt
COPY expected_stdout /stdout
COPY --from=build /opt/server/target/release/server /server
COPY --from=build2 /tmp/$name $name
EXPOSE $port
CMD /server --diffs 3 --port $PORT --ref-elf $NAME --flag flag.txt --ref-stdout stdout
