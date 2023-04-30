NAME := nope
CFLAGS := -masm=intel -w

all: $(NAME).c
	gcc $(NAME).c -o $(NAME) -masm=intel -w

dist: Dockerfile
	docker build -t $(NAME) .
	docker run -d --name $(NAME) $(NAME)
	docker cp $(NAME):/$(NAME) ./$(NAME)

clean:
	docker rm -f $(NAME)
	docker rmi $(NAME)
	rm $(NAME)
