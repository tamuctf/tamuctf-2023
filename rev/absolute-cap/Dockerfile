FROM rust:alpine as build

RUN apk update
RUN apk add --no-cache openssl-dev musl-dev

ADD Cargo.toml Cargo.toml
ADD Cargo.lock Cargo.lock
ADD friend friend
ADD proto proto
ADD server server
ADD launcher launcher

RUN cargo build --release

ADD flag.txt flag.txt
RUN chmod 400 flag.txt

FROM scratch

COPY --from=build /proc /proc
COPY --from=build /target/release/friend /friend
COPY --from=build /target/release/server /server
COPY --from=build /target/release/launcher /launcher
COPY --from=build /flag.txt /flag.txt

USER 0

ENTRYPOINT ["/launcher"]
