NAME := absolute-cap
PORT := 16983

run: docker
	docker run -d --cap-add cap_sys_nice --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME)

clean: .PHONY
	docker container rm -f $(NAME)
	rm -f $(NAME)

docker: Dockerfile Cargo.toml friend server
	docker buildx build -t $(NAME) --build-arg name=$(NAME) .

extract: docker
	$(eval id := $(shell docker create $(NAME)))
	mkdir -p binaries
	docker cp $(id):/server - | tar -C binaries -xv server
	docker cp $(id):/friend - | tar -C binaries -xv friend
	docker rm -v $(id)

dist: extract server
	zip -r $(NAME).zip binaries server

.PHONY:
