NAME := shmooving
PORT := 7773

run: docker
	docker run -d --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

clean: .PHONY
	docker container rm -f $(NAME)
	rm -f $(NAME)

docker: Dockerfile ./src/main.rs
	touch flag.txt
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) .

extract: docker
	$(eval id := $(shell docker create $(NAME)))
	docker cp $(id):/crypto/$(NAME) $(NAME)
	docker rm -v $(id)

dist: extract
	zip -r $(NAME).zip $(NAME) $(NAME) Cargo.toml Dockerfile Makefile src
.PHONY:

