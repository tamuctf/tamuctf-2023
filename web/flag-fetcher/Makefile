NAME := flag-fetcher
PORT := 8080

run: docker
	docker run -d --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

clean: .PHONY
	docker container rm -f $(NAME)
	rm -f $(NAME)

docker: Dockerfile Cargo.toml ./src/main.rs
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) .

dist: Cargo.toml ./src/main.rs ./index.html ./static/runtime.js
	zip $(NAME).zip Cargo.toml src/main.rs index.html static/runtime.js

.PHONY:
