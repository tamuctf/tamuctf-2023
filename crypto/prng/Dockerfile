FROM python:slim-buster

ARG port

RUN apt-get update -y; apt-get install socat -y

COPY flag.py /crypto/flag.py
COPY server.py /crypto/server.py
WORKDIR /crypto

RUN echo "exec socat -s TCP-LISTEN:$port,reuseaddr,fork EXEC:\"python3 /crypto/server.py\",stderr" > /crypto/docker_entrypoint.sh

ENTRYPOINT ["sh", "/crypto/docker_entrypoint.sh"]
