CC := $(or $(CC),gcc)
CFLAGS := -fno-stack-protector -w -masm=intel -no-pie
NAME := inspector_gadget
PORT := 7005
all: $(NAME)

clean: .PHONY
	docker container rm -f $(NAME)
	docker rmi -f $(NAME)
	rm -f $(NAME) $(NAME).zip libc.so.6 

all:
	$(CC) $(CFLAGS) $(NAME).c -o $(NAME)

docker: Dockerfile 
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) .

run: docker
	docker run -d --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

extract: docker
	$(eval id := $(shell docker create $(NAME)))
	docker cp $(id):/pwn/$(NAME) $(NAME)
	docker cp $(id):/lib/x86_64-linux-gnu/libc-2.28.so libc.so.6
	docker rm -v $(id)

dist: extract
	zip $(NAME).zip $(NAME) libc.so.6 

.PHONY:

