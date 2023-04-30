NAME := flag-encryptor

all: $(NAME).c
	gcc -o $(NAME) $(NAME).c tiny-AES-c/aes.c
	python3 enc.py $(NAME)
	strip $(NAME)
	./$(NAME)

dist: Dockerfile
	docker build -t $(NAME) .
	docker run -d --name $(NAME) $(NAME)
	docker cp $(NAME):/$(NAME) ./$(NAME)
	docker cp $(NAME):/flag.png ./flag.png
	zip $(NAME).zip $(NAME) flag.png

clean:
	rm -f $(NAME).zip $(NAME) flag.png
	docker rm -f $(NAME)
	docker rmi $(NAME)
