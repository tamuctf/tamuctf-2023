CC := gcc
CFLAGS :=
PORT := 8000
NAME := eyepatch

$(NAME): $(NAME).c
	$(CC) $(CFLAGS) $^ -o $@

clean: .PHONY
	docker container rm -f $(NAME)
	rm -f $(NAME) $(NAME).zip

docker:
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) .

dist: docker
	$(eval id := $(shell docker create $(NAME)))
	docker cp $(id):/$(NAME) $(NAME)
	docker rm -v $(id)
	zip $(NAME).zip $(NAME) expected_stdout

run: docker
	docker run -d --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

.PHONY:
