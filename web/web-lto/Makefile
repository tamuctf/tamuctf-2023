NAME := web-lto
PORT := 8937

all: docker dist

clean: .PHONY
	docker container rm -f $(NAME)
	rm -f $(NAME).zip

docker: Dockerfile
	docker build -t $(NAME) --build-arg port=$(PORT) .

run: docker
	docker run -d --read-only --restart=always --tmpfs=/tmp --name $(NAME) -p $(PORT):$(PORT) $(NAME)

dist: web-lto/Cargo.toml web-lto/src/main.rs index.html
	zip $(NAME).zip $^

.PHONY:
