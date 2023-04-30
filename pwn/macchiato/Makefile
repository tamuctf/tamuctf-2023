NAME := macchiato
PORT := 7010

run: docker
	docker run -d --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

clean:
	docker container rm -f $(NAME)
	rm -f $(NAME).zip

docker:
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) .

dist:
	zip -r $(NAME).zip src Makefile Dockerfile
