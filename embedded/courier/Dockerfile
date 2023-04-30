FROM ubuntu

ARG port

RUN apt update; apt -y install qemu-system-arm socat

COPY target/thumbv7m-none-eabi/release/courier /opt/chal/courier
COPY target/thumbv7m-none-eabi/release/consignee /opt/chal/consignee

ADD entrypoint.sh /opt/chal/entrypoint.sh
RUN chmod +x /opt/chal/entrypoint.sh

ENV PORT ${port}

WORKDIR /tmp

CMD ["bash", "-c", "socat -d -d TCP-LISTEN:$PORT,reuseaddr,fork EXEC:/opt/chal/entrypoint.sh"]
