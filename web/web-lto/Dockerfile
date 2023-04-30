FROM rust:slim-buster as build

RUN apt update && apt -y --autoremove install pkg-config libssl-dev

ADD flag-uploader flag-uploader
ADD web-lto web-lto
ADD Cargo.toml Cargo.toml
ADD Cargo.lock Cargo.lock

RUN cargo build --release

FROM debian:buster-slim

RUN apt update && apt -y --autoremove install libssl-dev socat
RUN rm -rf /etc/cron.*/*

COPY --from=build target/release/flag-uploader /usr/bin/flag-uploader
COPY --from=build target/release/web-lto /usr/bin/web-lto

ADD flag.txt /root/flag.txt
ADD index.html /var/www/index.html
ADD challenge.sh /root/challenge.sh
RUN chmod +x /root/challenge.sh

ARG port
EXPOSE $port
ENV PORT=$port 

CMD ["bash", "-c", "socat -d -d TCP-LISTEN:$PORT,reuseaddr,fork EXEC:/root/challenge.sh"]
