CC := $(or $(CC),gcc)
NAME := pwnme
LIB := foo
PORT := 7004
CFLAGS1 := -c -fpic -w
CFLAGS2 := -shared
CFLAGS3 := -L./ -Wl,-rpath=./ -l$(NAME) -lc -no-pie -fno-stack-protector -masm=intel

clean: .PHONY
	docker container rm -f $(NAME)
	docker rmi -f $(NAME)
	rm -f $(NAME) $(NAME).zip lib$(NAME).so 

all:
	$(CC) $(CFLAGS1) $(LIB).c
	$(CC) $(CFLAGS2) -o lib$(NAME).so $(LIB).o
	$(CC) $(CFLAGS3) -o $(NAME) $(NAME).c 

docker: Dockerfile
	docker build -t $(NAME) --build-arg name=$(NAME) --build-arg port=$(PORT) --build-arg lib=$(LIB) .

run: docker
	docker run -d --read-only --restart=always --name $(NAME) -p $(PORT):$(PORT) $(NAME) lib=$(LIB)

extract: docker
	$(eval id := $(shell docker create $(NAME)))
	docker cp $(id):/pwn/$(NAME) $(NAME)
	docker cp $(id):/pwn/lib$(NAME).so lib$(NAME).so
	docker rm -v $(id)

dist: extract 
	zip $(NAME).zip $(NAME) lib$(NAME).so

.PHONY:


#gcc -shared -o lib$(LIB)e2.so $(LIB)o
#gcc -L./ -o vuln chall.c -l$(LIB)e2  -lc -fno-stack-protector -no-pie

#clean:
#	rm $(LIB)o lib$(LIB)e2.so vuln

