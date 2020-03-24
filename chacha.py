from cryptopals_lib import * 
from copy import copy

def chacha_key_generation(iv, key, position=0):
	'''
	|"expa"|"nd 3"|"2-by"|"te k"|
	|Key   |Key   |Key   |Key   |
	|Key   |Key   |Key   |Key   |
	|Pos.  |Pos.  |Nonce |Nonce |
	'''
	#First row of 4 ints
	#If it is a 128 bit key just repeat the key
	if len(key) == 16:
		out_key = b"expand 16-byte k"
		out_key += key
	else:
		out_key = b"expand 32-byte k"
	
	# Second and Third Row of key data
	out_key += key

	#Fourth Row of position and IV
	out_key += int_to_bytes(position).rjust(8, b'\x00') + iv

	return out_key


def hchacha_key_generation(iv, key):
	'''
	|"expa"|"nd 3"|"2-by"|"te k"|
	|Key   |Key   |Key   |Key   |
	|Key   |Key   |Key   |Key   |
	|Nonce |Nonce |Nonce |Nonce |
	'''
	#First row of 4 ints
	#If it is a 128 bit key just repeat the key
	if len(key) == 16:
		out_key = b"expand 16-byte k"
		out_key += key
	else:
		out_key = b"expand 32-byte k"
	
	# Second and Third Row of key data
	out_key += key

	#Fourth Row of position and IV
	out_key += iv

	return out_key

def salsa_key_generation(iv, key, position=0):
	'''
	|"expa"|Key   |Key   |Key   |
	|Key   |"nd 3"|Nonce |Nonce |
	|Pos.  |Pos.  |"2-by"|Key   |
	|Key   |Key   |Key   |"te k"|
	'''

	#If a 128 bit key repeat the key
	if len(key) == 16:
		out_key =  b"expa" + key + b"nd 1"
		out_key += iv + int_to_bytes(position).rjust(8, b'\x00') 
		out_key += b"6-by" + key + b"te k"
	else:
		out_key =  b"expa" + key[:16] + b"nd 3"
		out_key += iv + int_to_bytes(position).rjust(8, b'\x00') 
		out_key += b"2-by" + key[16:] + b"te k"

	return out_key

def hsalsa_key_generation(iv, key):
	'''
	|"expa"|Key   |Key   |Key   |
	|Key   |"nd 3"|Nonce |Nonce |
	|Pos.  |Pos.  |"2-by"|Key   |
	|Key   |Key   |Key   |"te k"|
	'''

	#If a 128 bit key repeat the key
	if len(key) == 16:
		out_key =  b"expa" + key + b"nd 1"
		out_key += iv
		out_key += b"6-by" + key + b"te k"
	else:
		out_key =  b"expa" + key[:16] + b"nd 3"
		out_key += iv
		out_key += b"2-by" + key[16:] + b"te k"

	return out_key

def salsa_quarter_round(a,b,c,d):
	b = asint32(b ^ shift_rotate_left(asint32(a + d), 7))
	c = asint32(c ^ shift_rotate_left(asint32(b + a), 9))
	d = asint32(d ^ shift_rotate_left(asint32(c + b), 13))
	a = asint32(a ^ shift_rotate_left(asint32(d + c), 18))

	return [a,b,c,d]


def chacha_quarter_round(a,b,c,d):
	a = asint32(a + b)
	d = asint32(d ^ a)
	d = asint32(shift_rotate_left(d, 16))

	c = asint32(c + d)
	b = asint32(b ^ c)
	b = asint32(shift_rotate_left(b, 12))

	a = asint32(b + a)
	d = asint32(d ^ a)
	d = asint32(shift_rotate_left(d, 8))

	c = asint32(d + c)
	b = asint32(b ^ c)
	b = asint32(shift_rotate_left(b, 7))

	return [a,b,c,d]


def hchacha_key_schedule(key_input, rounds=20):
	#print(f"Intial State: {key_input}")

	temp_round = copy(key_input)

	#Do 10 Rounds of both rows and diagonals
	for i in range(rounds//2):

		#Do Each Column
		temp_round[0], temp_round[4], temp_round[8],  temp_round[12] = chacha_quarter_round(temp_round[0], temp_round[4], temp_round[8],  temp_round[12])
		temp_round[1], temp_round[5], temp_round[9],  temp_round[13] = chacha_quarter_round(temp_round[1], temp_round[5], temp_round[9],  temp_round[13])
		temp_round[2], temp_round[6], temp_round[10], temp_round[14] = chacha_quarter_round(temp_round[2], temp_round[6], temp_round[10], temp_round[14])
		temp_round[3], temp_round[7], temp_round[11], temp_round[15] = chacha_quarter_round(temp_round[3], temp_round[7], temp_round[11], temp_round[15])
			

		#Do Each Diagonal
		temp_round[0], temp_round[5], temp_round[10], temp_round[15] = chacha_quarter_round(temp_round[0], temp_round[5], temp_round[10], temp_round[15])
		temp_round[1], temp_round[6], temp_round[11], temp_round[12] = chacha_quarter_round(temp_round[1], temp_round[6], temp_round[11], temp_round[12])
		temp_round[2], temp_round[7], temp_round[8],  temp_round[13] = chacha_quarter_round(temp_round[2], temp_round[7], temp_round[8],  temp_round[13])
		temp_round[3], temp_round[4], temp_round[9],  temp_round[14] = chacha_quarter_round(temp_round[3], temp_round[4], temp_round[9],  temp_round[14])

	#print(f"Full Subkey: {temp_round}")
	return intarray_to_bytes(temp_round[:4] + temp_round[-4:], 4)

def hsalsa_key_schedule(key_input, rounds=20):
	#print(f"Intial State: {key_input}")
		
	temp_round = copy(key_input)

	#Do 10 Rounds of both rows and diagonals
	for i in range(rounds//2):

		#Do Each Column Shifted down
		temp_round[0],  temp_round[4],  temp_round[8],  temp_round[12] = salsa_quarter_round(temp_round[0],  temp_round[4],  temp_round[8],  temp_round[12])
		temp_round[5],  temp_round[9],  temp_round[13], temp_round[1]  = salsa_quarter_round(temp_round[5],  temp_round[9],  temp_round[13], temp_round[1])
		temp_round[10], temp_round[14], temp_round[2],  temp_round[6]  = salsa_quarter_round(temp_round[10], temp_round[14], temp_round[2],  temp_round[6])
		temp_round[15], temp_round[3],  temp_round[7],  temp_round[11] = salsa_quarter_round(temp_round[15], temp_round[3],  temp_round[7],  temp_round[11])

		#Do Each Row
		temp_round[0],  temp_round[1],  temp_round[2],  temp_round[3]  = salsa_quarter_round(temp_round[0],  temp_round[1],  temp_round[2],  temp_round[3])
		temp_round[5],  temp_round[6],  temp_round[7],  temp_round[4]  = salsa_quarter_round(temp_round[5],  temp_round[6],  temp_round[7],  temp_round[4])
		temp_round[10], temp_round[11], temp_round[8],  temp_round[9]  = salsa_quarter_round(temp_round[10], temp_round[11], temp_round[8],  temp_round[9])
		temp_round[15], temp_round[12], temp_round[13], temp_round[14] = salsa_quarter_round(temp_round[15], temp_round[12], temp_round[13], temp_round[14])

	#print(f"Full Subkey: {intarray_to_bytes(temp_round,4).hex()}")
	return intarray_to_bytes([temp_round[0], temp_round[5], temp_round[10], temp_round[15]] + temp_round[6:10], 4)

def salsa_key_schedule(key_input, rounds=20):
	temp_round = copy(key_input)

	#Do 10 Rounds of both rows and diagonals
	for i in range(rounds//2):

		#Do Each Column Shifted down
		temp_round[0],  temp_round[4],  temp_round[8],  temp_round[12] = salsa_quarter_round(temp_round[0],  temp_round[4],  temp_round[8],  temp_round[12])
		temp_round[5],  temp_round[9],  temp_round[13], temp_round[1]  = salsa_quarter_round(temp_round[5],  temp_round[9],  temp_round[13], temp_round[1])
		temp_round[10], temp_round[14], temp_round[2],  temp_round[6]  = salsa_quarter_round(temp_round[10], temp_round[14], temp_round[2],  temp_round[6])
		temp_round[15], temp_round[3],  temp_round[7],  temp_round[11] = salsa_quarter_round(temp_round[15], temp_round[3],  temp_round[7],  temp_round[11])

		#Do Each Row
		temp_round[0],  temp_round[1],  temp_round[2],  temp_round[3]  = salsa_quarter_round(temp_round[0],  temp_round[1],  temp_round[2],  temp_round[3])
		temp_round[5],  temp_round[6],  temp_round[7],  temp_round[4]  = salsa_quarter_round(temp_round[5],  temp_round[6],  temp_round[7],  temp_round[4])
		temp_round[10], temp_round[11], temp_round[8],  temp_round[9]  = salsa_quarter_round(temp_round[10], temp_round[11], temp_round[8],  temp_round[9])
		temp_round[15], temp_round[12], temp_round[13], temp_round[14] = salsa_quarter_round(temp_round[15], temp_round[12], temp_round[13], temp_round[14])

	#Add the previous key_schedule and the current temp_round 
	#Then get only the 32bits of 
	for i in range(16):
		temp_round[i] = asint32(temp_round[i] + key_input[i])

	return temp_round


def chacha_key_schedule(key_input, rounds=20):
	temp_round = copy(key_input)

	#Do 10 Rounds of both rows and diagonals
	for i in range(rounds//2):

		#Do Each Column
		temp_round[0], temp_round[4], temp_round[8],  temp_round[12] = chacha_quarter_round(temp_round[0], temp_round[4], temp_round[8],  temp_round[12])
		temp_round[1], temp_round[5], temp_round[9],  temp_round[13] = chacha_quarter_round(temp_round[1], temp_round[5], temp_round[9],  temp_round[13])
		temp_round[2], temp_round[6], temp_round[10], temp_round[14] = chacha_quarter_round(temp_round[2], temp_round[6], temp_round[10], temp_round[14])
		temp_round[3], temp_round[7], temp_round[11], temp_round[15] = chacha_quarter_round(temp_round[3], temp_round[7], temp_round[11], temp_round[15])
			

		#Do Each Diagonal
		temp_round[0], temp_round[5], temp_round[10], temp_round[15] = chacha_quarter_round(temp_round[0], temp_round[5], temp_round[10], temp_round[15])
		temp_round[1], temp_round[6], temp_round[11], temp_round[12] = chacha_quarter_round(temp_round[1], temp_round[6], temp_round[11], temp_round[12])
		temp_round[2], temp_round[7], temp_round[8],  temp_round[13] = chacha_quarter_round(temp_round[2], temp_round[7], temp_round[8],  temp_round[13])
		temp_round[3], temp_round[4], temp_round[9],  temp_round[14] = chacha_quarter_round(temp_round[3], temp_round[4], temp_round[9],  temp_round[14])

	#Add the previous key_schedule and the current temp_round 
	#Then get only the 32bits of 
	for i in range(16):
		temp_round[i] = asint32(temp_round[i] + key_input[i])

	return temp_round

def xsalsa_encrypt(iv, key, message, rounds=20):
	#Geneate sub key 
	master_key_input = hsalsa_key_generation(iv[:16], key)
	#print(master_key_input, len(master_key_input))
	master_key_schedule = bytes_to_intarray(master_key_input, 4)

	#for x in master_key_schedule:
	#	print(int_to_bytes(x).hex())

	sub_key = hsalsa_key_schedule(master_key_schedule, rounds)
	print(f"SubKey: {sub_key.hex()}")
	return salsa_encrypt(iv[16:24].rjust(8, b'\x00'), sub_key, message, rounds)


def salsa_encrypt(iv, key, message, rounds=20, inital_pos=0):
	if len(message) == 0:
		return

	#Initialize output
	ciphertext = b""

	#Generate key box
	key_input = salsa_key_generation(iv, key, inital_pos)
	#print(key_input, len(key_input))
	key_schedule = bytes_to_intarray(key_input, 4)

	for index, message_block in enumerate(to_blocks(message, 64)):
		#Encrypt the message
		round_key = salsa_key_schedule(key_schedule, rounds)
		print(f"Key Stream: {intarray_to_bytes(round_key, 4).hex()}")

		#Update the position in the key_schedule
		key_schedule[8] = asint32((inital_pos + index + 1))
		key_schedule[9] = asint32((inital_pos + index + 1) >> 32 )
		#print(f"KeySchedule2: {key_schedule}")

		#Convert key_input to byte string and xor against the message
		ciphertext += shortest_xor(message_block, intarray_to_bytes(round_key, 4))

	return ciphertext


def xchacha_encrypt(iv, key, message, rounds=20):
	#Geneate sub key 
	master_key_input = hchacha_key_generation(iv[:16], key)
	#print(master_key_input, len(master_key_input))
	master_key_schedule = bytes_to_intarray(master_key_input, 4)

	#for x in master_key_schedule:
	#	print(int_to_bytes(x).hex())

	sub_key = hchacha_key_schedule(master_key_schedule, rounds)
	print(f"SubKey: {sub_key.hex()}")

	return chacha_encrypt(iv[16:24].rjust(8, b'\x00'), sub_key, message, rounds)

def chacha_encrypt(iv, key, message, rounds=20, inital_pos=0):
	if len(message) == 0:
		return

	#Initalize output
	ciphertext = b""

	#Geneate key box
	key_input = chacha_key_generation(iv, key, inital_pos)
	#print(key_input.hex(), len(key_input))
	key_schedule = bytes_to_intarray(key_input, 4)

	for index, message_block in enumerate(to_blocks(message, 64)):
		#Encrypt the message
		round_key = chacha_key_schedule(key_schedule, rounds)
		print(f"Key Stream: {intarray_to_bytes(round_key, 4).hex()}")

		#Update the position in the key_schedule by adding one
		key_schedule[12] = asint32((inital_pos + index + 1))
		key_schedule[13] = asint32((inital_pos + index + 1) >> 32 )
		#print(f"KeySchedule2: {key_schedule}")

		#Convert key_input to byte string and xor against the message
		ciphertext += shortest_xor(message_block, intarray_to_bytes(round_key, 4))

	return ciphertext

if __name__ == '__main__':
	#Test 128 bit ChaCha20 https://github.com/secworks/chacha_testvectors/blob/master/src/chacha_testvectors.txt
	key = bytes.fromhex("c46ec1b18ce8a878725a37e780dfb735")
	iv =  bytes.fromhex("1ada31d5cf688221")
	ciphertext = chacha_encrypt(iv, key, b"Test"*30)
	print(f"Ciphertext: {ciphertext.hex()}")
	#Key stream 1: 826abdd84460e2e9349f0ef4af5b179b426e4b2d109a9c5bb44000ae51bea90a496beeef62a76850ff3f0402c4ddc99f6db07f151c1c0dfac2e56565d6289625
	#Key stream 2: 5b23132e7b469c7bfb88fa95d44ca5ae3e45e848a4108e98bad7a9eb15512784a6a9e6e591dce674120acaf9040ff50ff3ac30ccfb5e14204f5e4268b90a8804

	#Test 256 bit ChaCha20 https://github.com/secworks/chacha_testvectors/blob/master/src/chacha_testvectors.txt
	key = bytes.fromhex("00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100")
	iv =  bytes.fromhex("0f1e2d3c4b5a6978")
	ciphertext = chacha_encrypt(iv, key, b"Test"*30)
	print(f"Ciphertext: {ciphertext.hex()}")
	#Key stream 1: 9fadf409c00811d00431d67efbd88fba59218d5d6708b1d685863fabbb0e961eea480fd6fb532bfd494b2151015057423ab60a63fe4f55f7a212e2167ccab931
	#Key stream 2: fbfd29cf7bc1d279eddf25dd316bb8843d6edee0bd1ef121d12fa17cbc2c574cccab5e275167b08bd686f8a09df87ec3ffb35361b94ebfa13fec0e4889d18da5

	#Test 128 bit Salsa20 https://github.com/alexwebr/salsa20/blob/master/test_vectors.128
	key = bytes.fromhex("0A5DB00356A9FC4FA2F5489BEE4194E7")
	iv =  bytes.fromhex("1F86ED54BB2289F0")
	ciphertext = salsa_encrypt(iv, key, b"Test"*30)
	print(f"Ciphertext: {ciphertext.hex()}")
	#Key stream 1: 8b354c8f8384d5591ea0ff23e7960472b494d04b2f787fc87b6569cb9021562ff5b1287a4d89fb316b69971e9b861a109cf9204572e3de7eab4991f4c7975427
	#Key stream 2: 5d33f4322125f8e89526e1ea1d83fbeb4e0905ac77e94f7e239a471087addc4dab09cdf55f06d01f833c9b909c108f9ee75c4331be50f583f525953051c7b70c

	#Test 256 bit Salsa20 https://github.com/alexwebr/salsa20/blob/master/test_vectors.256
	key = bytes.fromhex("0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417")
	iv =  bytes.fromhex("1F86ED54BB2289F0")
	ciphertext = salsa_encrypt(iv, key, b"Test"*30)
	print(f"Ciphertext: {ciphertext.hex()}")
	#Key stream 1: 3fe85d5bb1960a82480b5e6f4e965a4460d7a54501664f7d60b54b06100a37ffdcf6bde5ce3f4886ba77dd5b44e95644e40a8ac65801155db90f02522b644023
	#Key stream 2: d5af60802b6fa74e3f2a5dbd4fa3f8b76e012ce9aa3a5747b96857a630f5462a0d21dd8d07ea722c72b31567eb7f4db1e6b3f03c0f3f2df4beb68a50d86df81a

	#Test XChaCha https://tools.ietf.org/id/draft-arciszewski-xchacha-01.html#rfc.section.2
	key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	iv =  bytes.fromhex("000000090000004a0000000031415927")
	ciphertext = xchacha_encrypt(iv, key, b"Test"*30)
	print(f"Ciphertext: {ciphertext.hex()}")
	#SubKey: 82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc
	#Key Stream: e5082ea6e894d4b62d38f23e2ea2d05039f7f513856a980147b6b439592e9cd33c06eefa3ceaa34deb0a3e8d32b73198897640e9efda66bfc2526f26a5c62c11
	#Key Stream: 88995280e9f0cd12d3ee63d0908da731abfabe363b1c3a6fc905f84897637cd866b7b254ecc6d03db4adfce9e183d2a1b7d60921352e39d1e6347c9a749db066

	#Test XChaCha https://tools.ietf.org/id/draft-arciszewski-xchacha-01.html#rfc.section.2
	key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	iv =  bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555658")
	plaintext = bytes.fromhex("5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e")
	ciphertext = xchacha_encrypt(iv, key, plaintext)
	print(f"Ciphertext: {ciphertext.hex()}")
	#SubKey: 4a8ac0c0296222bafe959faabe06a45b89a3cee444fef6e3d77659a53f49ee32
	#Ciphertext: 4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a66393b93111c1a55dd7421a10184974c7c5

	#Test XSalsa http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
	key = bytes.fromhex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
	iv =  bytes.fromhex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
	#plaintext = bytes.fromhex(b"Test"*30)
	ciphertext = xsalsa_encrypt(iv, key, b"Test"*30)
	print(f"Ciphertext: {ciphertext.hex()}")
	#SubKey: dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4
	#Key Stream: eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880309e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c093c5e55855796
	#Key Stream: 25337bd3ab619d615760d8c5b224a85b1d0efe0eb8a7ee163abb0376529fcc09bab506c618e13ce777d82c3ae9d1a6f972d4160287cbfe60bf2130fc0a6ff604
