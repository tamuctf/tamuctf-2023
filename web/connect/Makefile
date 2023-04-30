NAME := connect
PORT := 8001

run:
	docker build -t $(NAME) .
	docker run --read-only -d --restart=always --name $(NAME) -p $(PORT):80 $(NAME)

stop:
	docker container rm -f $(NAME)

dist:
	zip -r $(NAME).zip src
