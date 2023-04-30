NAME := courier
PORT := 42069

all: dist docker

stamp.key:
	head -c64 /dev/urandom > stamp.key

docker: Dockerfile stamp.key
	cargo build --release --features debug --target thumbv7m-none-eabi -p courier -p consignee
	docker build -t $(NAME) --build-arg port=$(PORT) .

run: stop docker dist
	docker run -d --read-only --restart=always --mount type=tmpfs,destination=/tmp --name $(NAME) -p $(PORT):$(PORT) $(NAME)

stop:
	docker rm -f $(NAME)

logs:
	docker logs -f $(NAME)

clean: stop
	docker rmi $(NAME)

dist: consignee courier courier-proto lm3s6965-uart sender stamper Cargo.lock Cargo.toml Dockerfile entrypoint.sh Makefile
	tar czvf courier.tar.gz $^

