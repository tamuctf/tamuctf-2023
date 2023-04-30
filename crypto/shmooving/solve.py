from pwn import *
import binascii

HOST = 'localhost'
PORT = 7773

characters = string.ascii_letters + string.digits
# array for knowning where to unshift all the bytes after the operations
unshift = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7]

r = remote(HOST, PORT)

r.recvuntil(b'flag:\n')
ctxt = r.recvline().decode().strip()
print("Here's the challenge to decrypt: %s" % ctxt)

# create blocks of each alphanumeric character to encrypt
ptxt = ""
for letter in characters:
	ptxt += letter * 16 
ptxt = binascii.hexlify(ptxt.encode())

# send the plaintext and receive the encrypted version
r.recvuntil(b'hex:')
r.sendline(ptxt)
r.recvuntil(b'blocks:\n')
enc = r.recvline().decode().strip()

decrypted = [''] * 16
response = ""
for i in range(len(ctxt) // 2):
	byte_c = ctxt[2 * i : 2 * (i+1)]

	if i == 16:
		response = "".join(decrypted)
		
	char_ind = i % 16
	
	# iterate through all letters and check to find the matching one
	for j in range(len(characters)):
		index = 32 * j + 2 * char_ind
		byte_e = enc[index : index + 2]

		# if we have a match add the character to the right spot
		if byte_e == byte_c:
			decrypted[unshift[char_ind]] = characters[j]

response += "".join(decrypted)
print("Decrypted version: %s" % response)
r.recvuntil(b'answer?')
r.sendline(response.encode())
r.recvuntil(b'flag:\n')
flag = r.recvline().decode().strip()

r.close()

print("The flag is: %s" % flag)
