FROM ubuntu:20.04

COPY ./auth-passwd.patch /
COPY ./flag.txt /home/billy/flag.txt
RUN apt update -y && \
    apt install -y build-essential zlib1g-dev libssl-dev wget && \
    useradd billy && \
    echo billy:w95WnHlqlfKUNsZLuqluWKxLmGJcRqYo | chpasswd && \
    groupadd -g 999 sshd && \
    useradd -u 999 -g 999 -c sshd -d / sshd && \
    mkdir /var/lib/sshd && \
    wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.0p1.tar.gz && \
    tar -xvf /openssh-9.0p1.tar.gz

WORKDIR /openssh-9.0p1
RUN patch -ruN < ../auth-passwd.patch && \
    ./configure && \
    make sshd && \
    make install && \
    rm -rf /openssh-9.0p1 /openssh-9.0p1.tar.gz /auth-passwd.patch

WORKDIR /

EXPOSE 22
ENTRYPOINT ["/usr/local/sbin/sshd", "-D", "-o", "ListenAddress=0.0.0.0"]

