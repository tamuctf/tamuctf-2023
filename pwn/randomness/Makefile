NAME := randomness
PORT := 6970
CFLAGS := -Wl,-z,norelro -no-pie -fno-stack-protector

all:
	gcc $(NAME).c -o $(NAME) $(CFLAGS)

docker: Dockerfile $(NAME)
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) .

run: docker
	docker run -d --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

clean:
	docker rm -f $(NAME)
	docker rmi $(NAME)
	rm $(NAME)

extract: docker
	$(eval id := $(shell docker create $(NAME)))
	docker cp $(id):/pwn/$(NAME) - | tar xv $(NAME)
	docker rm -v $(id)

dist: extract
	zip $(NAME).zip $(NAME) $(NAME).c
