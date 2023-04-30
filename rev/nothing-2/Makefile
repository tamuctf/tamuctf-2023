NAME := nothing-2

all: $(NAME).c
	gcc $(NAME).c -s -o $(NAME)
	strip $(NAME)

dist: Dockerfile
	docker build -t $(NAME) .
	docker run -d --name $(NAME) $(NAME)
	docker cp $(NAME):/$(NAME) ./$(NAME)
	zip $(NAME).zip $(NAME)

clean:
	rm -f $(NAME).zip $(NAME)
	docker rm -f $(NAME)
	docker rmi $(NAME)
