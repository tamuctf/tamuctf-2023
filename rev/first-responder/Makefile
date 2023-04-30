NAME := firstresponder
PORT := 4444

all: clean dist

clean:
	docker container rm -f tamuctf-$(NAME)
	rm -f $(NAME).zip

dist: docker
	docker cp tamuctf-$(NAME):/usr/local/sbin/sshd sshd
	zip $(NAME).zip sshd
	rm sshd

docker: 
	docker build -t $(NAME) .
	docker run -d --restart=always --name tamuctf-$(NAME) -p $(PORT):22 $(NAME)

.PHONY:
