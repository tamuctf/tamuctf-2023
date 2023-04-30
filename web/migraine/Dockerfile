FROM node:19-buster-slim

ARG name
ARG port

COPY flag.txt /flag.txt
COPY src/ /app
WORKDIR app
RUN npm install

EXPOSE 8040
ENTRYPOINT ["node", "app.js"]
