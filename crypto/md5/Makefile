NAME := diffiecc
PORT := 7001

docker: Dockerfile
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) .

run: docker
	docker run -d --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

dist:
	zip $(NAME).zip server.py

clean:
	docker kill $(NAME) ; docker rm $(NAME) ; docker rmi $(NAME)

