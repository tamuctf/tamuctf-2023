FROM python:3.8-slim-buster

COPY src/ /
COPY flag.txt /
RUN apt update -y && apt upgrade -y && apt install -y curl && pip3 install flask

ENTRYPOINT ["python3", "/app.py"]
