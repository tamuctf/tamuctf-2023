FROM python:slim-buster

ARG port

RUN apt-get update -y; apt-get install socat -y

COPY flag.txt /flag.txt
COPY server.py /server.py

RUN echo "exec socat -s TCP-LISTEN:$port,reuseaddr,fork EXEC:\"python3 /server.py\",stderr" > /docker_entrypoint.sh

ENTRYPOINT ["sh", "/docker_entrypoint.sh"]
