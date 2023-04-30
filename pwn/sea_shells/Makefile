CC := $(or $(CC),gcc) 
CFLAGS := -w -fno-stack-protector -z execstack 
NAME := sea_shells
PORT := 9999
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
	docker run -d --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

extract: docker
	$(eval id := $(shell docker create $(NAME)))
	docker cp $(id):/pwn/$(NAME) - | tar xv $(NAME)
	docker rm -v $(id)

dist: extract
	zip $(NAME).zip $(NAME) $(NAME).c solver-template.py

.PHONY:
