NAME := migraine
PORT := 8000

run: docker
	docker run -d --name $(NAME) -p $(PORT):$(PORT) migrane

docker:
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) .

clean:
	docker container rm -f $(NAME)

dist:
	zip -r $(NAME).zip src Dockerfile Makefile
