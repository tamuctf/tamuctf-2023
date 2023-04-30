ct = "hmtonazyvdgipzqzoffvayfubnmwcjprqipslnlyonfdhndoofdjtahhmqhkgcsunoydiqmggkapmootkxwaullpzxkyxedsoagoknwfxeprnfqkdfsywdgdlcmjbjaumkwghumgbzdnnkqtlmiiojauujaprdtchsdpvasnanfcmzvptkxubgmxoaifgjdakyjmusawgjhvkrxghnorujdraunlcnnipwhrttoupovprcngdlmiiojfugstdpemtmodgerlwnogbljkgawprnofpkckaadagprfbnfrytkuypemihoygpebjfcpgruarzkifgxqmuajplvqzpvmpktjdgccuttgwrvtffwettfdcsztzlylyggdajvypkkqmegowuwoyzfhpdnoapmagnklgifnwganfwxepilmmchsypvhnagninbrwdxdgnduqmursbhhmawzehovfdgciagctgblcptkxrpcgmllggixnzpvfgvvrnfjolizvgsouuejhvkromhnoapxyfuiouhnkvpvffdgrzunorfqoiogslgdkryynudpemtmaggeplepjgwiatgawprnofpkdotcnfnkjmpoekrcngdlcmjbrfdpdgnmfzrsougprprnofpkxgvpynuupfgvvrnfjolavtyefnfwjopvvzeendlrqolrfupjrdiiarpryjmunkvpvffdgrekkktfqbrwgvvgaifgjdzotxgmjptpjhvkrxgphryppilfdvipjwurxyfuwvvganawjhlmmotfoalfrrfffnoyefrmpertzqmghrmmdjfpucqmuakyfkrmtcgqkjgyykrlwztkhdgipshkaypihoywmeqzppvpmoggnkonadnoenypbjnwtmvocmklghvprpxgphoeaeydtdyuqzhlgjdykalqmuwawmpokplapmxayxdhobvqmufdipsztlnlpoekrnkgdlxaxojauulokvvzeendlaaqtfflmwndpvasnanfcrfdlrkxgnlfbjvsprxyfugvxoaifgjdhobvqefmrtjhvkrxgpnozlyffaiqqghkvpvffdgrtgbllamhldiwutzjaujhvkrxgphridrhtaufhpoekrnngdllmrsouifsgdpemtmodglvxdlagwhsogihhzpatyefdpvasnanfcgreptkxjrtfgvvrnfjolsljeeonktaopvpaoendlyaiaoazmcnnmuvqtaunmxornfjolidemyefuejhvkrxgphrfpxyfuiowphvvpvffdgrzwhrrfuoiogslgyvrytkudpemtmodglidepjgwiawgprhrnofpkdotnknipjmpoekrnkogoymjbrfdpeoijuarsouymagaonzspakquaojwlnijjsdzmrjafl"

alpha = 'abcdefghijklmnopqrstuvwxyz'


def encrypt(msg, key):
	ctxt = ''

	for i in range(len(msg)):
		index = alpha.index(msg[i]) ^ alpha.index(key[i % len(key)])
		if index < 26:
			ctxt += alpha[index]
		else:
			ctxt += msg[i]
		
		if i % len(key) == len(key) - 1:
			key = key[1:] + key[0]

	return ctxt


def decrypt(ct, key):
    pt = ''

    for i in range(len(ct)):
        idx = alpha.index(ct[i]) ^ alpha.index(key[i%len(key)])
        if idx < 26:
            pt += alpha[idx]
        else:
            pt += ct[i]

        if i % len(key) == len(key) - 1:
            key = key[1:] + key[0]

    return pt


assert(decrypt(encrypt('testingsuperlongstringtomakesuredecryptencryptaregoodabcdefghijklmnopqrstuvwxyz', 'abcd'), 'abcd') == 'testingsuperlongstringtomakesuredecryptencryptaregoodabcdefghijklmnopqrstuvwxyz')

assert(decrypt(encrypt('abcdefghijklmnopqrstuvwxyz', 'f'), 'f') == 'abcdefghijklmnopqrstuvwxyz')

def unrotate_helper(s, i):
    l = len(s)
    return s[l - i:] + s[:l - i]


def unrotate(ct, key_len):
    pt = ''
    for i in range(0, len(ct), key_len):
        substr = ct[i:i+key_len]
        pt += unrotate_helper(substr, (i//key_len) % key_len)
    return pt


assert(unrotate("ABCDBCDACDABDABC", 4) == "ABCDABCDABCDABCD")


def ic(ct):
    ret = 0.0
    den = ((len(ct)*(len(ct)-1))+0.0 / len(alpha))
    for a in alpha:
        n = ct.count(a)
        ret += (n*(n-1)) / den
    return ret

def expand_key(k):
    l = len(k)
    ret = ''
    for i in range(l):
        ret += k[i:l]+k[:i]
    return ret


#for i in range(1, 50):
#    temp = unrotate(ct, i)
#    s = 0.0
#    for j in range(i):
#        s += ic( temp[j:len(ct):i] )
#
#    print(s/i , i)

keylen = 13

unrotated_ct = unrotate(ct, 13)
sets = []
for i in range(13):
    sets.append(unrotated_ct[i::13])

F = [0.084, 0.014, 0.028, 0.038, 0.131, 0.029, 0.020, 0.053, 0.064, 0.001, 0.004, 0.034, 0.025, 0.071, 0.080, 0.020, 0.001, 0.068, 0.061, 0.105, 0.025, 0.009, 0.015, 0.002, 0.020, 0.001]

key = ''
for s in sets:
    best = ('z', 1.0)
    for a in alpha:
        total = 0.0
        counts = [0]*26
        temp = decrypt(s, a)
        for c in temp:
            counts[alpha.index(c)] += 1
        for i in range(26):
            counts[i] /= len(s)
            total += pow((counts[i] - F[i]) , 2) / F[i]
        if total < best[1]:
            best = (a, total)
    key += best[0]
print(key)

print(decrypt(ct, key))
