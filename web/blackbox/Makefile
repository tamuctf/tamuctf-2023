start:
	tar -xvf git.tar.gz
	docker build -t blackbox .
	docker run -d --restart=always --name tamuctf-blackbox -p 8000:80 blackbox
	rm -rf git
stop:
	docker container rm -f tamuctf-blackbox
