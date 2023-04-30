CC := $(or $(CC),gcc)
CFLAGS := -w
NAME := encryptinator
PORT := 9001
all: $(NAME)

clean: .PHONY
	rm -f $(NAME)
	docker rm -f $(NAME)
	docker rmi $(NAME)

$(NAME): $(NAME).c
	$(CC) $(CFLAGS) $^ -o $@

docker: Dockerfile
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) .

run: docker
	docker run -d --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

extract: docker
	$(eval id := $(shell docker create $(NAME)))
	docker cp $(id):/pwn/$(NAME) $(NAME)
	docker rm -v $(id)

dist: extract
	zip $(NAME).zip $(NAME) $(NAME).c 

.PHONY:
