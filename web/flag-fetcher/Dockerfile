FROM ekidd/rust-musl-builder as build

ADD Cargo.toml Cargo.toml
ADD Cargo.lock Cargo.lock
ADD src/ src/

RUN openssl genpkey -algorithm ED25519 > key

RUN cargo build --release

FROM scratch

COPY --from=build /home/rust/src/target/x86_64-unknown-linux-musl/release/flag-fetcher /flag-fetcher
COPY --from=build /home/rust/src/key /key
COPY index.html /index.html
COPY static/ /static/

EXPOSE 8080

CMD ["/flag-fetcher", "gigem{the_root_of_all_evil_b8c3c530}"]
