import numpy as np
import galois

GF = galois.GF(2)
columns = [] 
ptxt = b'Good luck with the challenge! :D'
flag = ''

# convert byte string to an array of binary values
def b_to_ar(b):
	b_int = int.from_bytes(b, 'big')
	x = []
	for i in range(128):
		mask = (1 << 127 - i)
		x.append((b_int & mask) >> 127 - i)
	return x

# convert binary matrix to its byte string
def matrix_to_byte(m):
	s = 0
	for i in range(128): 
		s *= 2 
		if m[i] > 0:
			s += 1
	return s.to_bytes(16, 'big')

# Read encrypted ciphertext and convert to a matrix
with open('encouragement.txt.enc', 'rb') as file:
	ctxt = file.read()

# Read in the encrypted flag
with open('flag.txt.enc', 'rb') as file:
	flag_enc = file.read()

# Read in the A matrix (as bytes) and convert to a 2D array
with open('A.data', 'rb') as file:
	data = file.read()
	for i in range(len(data) // 16):
		row = data[16 * i : 16 * (i + 1)]
		bit_str = b_to_ar(row)
		columns.append(bit_str)

# Convert the array to a galois field and compute its inverse
A = GF(columns)
A_inv = np.linalg.inv(A)

# We will calculate the K matrix with our known plaintext/ciphertext pair
c = GF(b_to_ar(ctxt[:16]))
p = GF(b_to_ar(ptxt[:16]))

# Use the known plaintext and ciphertext pair to calculate the K vector (K = A * p - c)
Ap = np.matmul(A, p)
K = c - Ap

# Now we shall decrypt the flag! p = A^-1 * (c - K)
for i in range(len(flag_enc) // 16):
	# Go through block by block
	block = flag_enc[16 * i: 16 * (i + 1)]
	block = GF(b_to_ar(block))

	# c - k
	ck = block - K

	# p = A^-1 * (c - K)
	plain = np.matmul(A_inv, ck)
	decoded = matrix_to_byte(plain)
	flag += decoded.decode()


print(flag)