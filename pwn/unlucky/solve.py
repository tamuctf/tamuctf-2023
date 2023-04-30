from pwn import *

host = '0.0.0.0'
port = 7777

r = remote(host, port)
p = process('./rand_nums')

r.recvuntil(b': ')
main = r.recvline()

# send the random number to our c program to get us the 7 numbers
numbers = []
p.recvuntil(b': ')
p.sendline(main)
for i in range(7):
	p.recvuntil(b': ')
	numbers.append(p.recvline().decode().strip())
p.close()

# now lets send those to the server
for num in numbers:
	# send in the 
	r.recvline()
	r.sendline(num)

# get the flag!
print(r.recvline().decode())

