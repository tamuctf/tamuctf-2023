from Crypto.Cipher import AES
from struct import unpack
from pathlib import Path

class Parser:
    def __init__(self, path):
        self.buf = Path(path).read_bytes()
        self.key = self.advance(32)
    def advance(self, n):
        ret = self.buf[:n]
        self.buf = self.buf[n:]
        return ret
    def get_len(self):
        big = self.advance(8)
        return unpack("<Q", big)[0]
    def parse_msg(self):
        n = self.get_len()
        ct = self.advance(n)
        iv = self.advance(12)
        aes = AES.new(self.key, AES.MODE_GCM, iv)
        pt = aes.decrypt(ct)
        return pt.decode()
    def decrypt(self):
        ret = []
        while len(self.buf) != 0:
            ret.append(self.parse_msg())
        return ret

for msg in Parser("stream").decrypt():
    print(msg)
