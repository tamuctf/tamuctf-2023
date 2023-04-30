CC := $(or $(CC),gcc)
CFLAGS := 
NAME := contrived-shellcode
PORT := 7000
all: $(NAME)

clean: .PHONY
	docker rm -f $(NAME)
	rm -f $(NAME)

$(NAME): $(NAME).c
	$(CC) $(CFLAGS) $^ -o $@

docker: Dockerfile $(NAME)
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) .

run: docker
	docker run -d --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

extract: docker
	$(eval id := $(shell docker create $(NAME)))
	docker cp $(id):/pwn/$(NAME) - | tar xv $(NAME)
	docker rm -v $(id)

dist: extract
	zip $(NAME).zip $(NAME) $(NAME).c

.PHONY:

