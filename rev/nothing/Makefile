NAME := nothing

all: $(NAME).c
	gcc $(NAME).c -s -o $(NAME)
	strip $(NAME)

dist: Dockerfile
	docker build -t $(NAME) .
	docker run -d --name $(NAME) $(NAME)
	docker cp $(NAME):/$(NAME) ./$(NAME)

clean:
	rm $(NAME)
	docker rm -f $(NAME)
	docker rmi $(NAME)
