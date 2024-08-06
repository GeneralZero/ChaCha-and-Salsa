import os, math, random, base64

letter_ranking = b"zqxjkvbpygfwmucldrh snioate"
b58alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


class PaddingError(Exception):
	pass


def frequency_score(plaintext):
	"""
	Returns a score representing how closely letter frequencies match the
	expected values found in the English language.
	"""

	return sum([-5 if letter_ranking.find(letter) == -1 else letter_ranking.find(letter) for letter in plaintext.lower()])

def best_single_bit_xor(ciphertext):
	best_score = 0
	best_plaintext = ""
	best_key = 0x00

	for i in range(0xFF):
		key_guess = bytes.fromhex('{0:02x}'.format(i))
		plaintext = fixedlen_xor(key_guess * len(ciphertext), ciphertext)
		#print(plaintext)
		score = frequency_score(plaintext)

		if score > best_score:
			best_plaintext, best_key, best_score = plaintext, key_guess, score

	return best_plaintext, best_key, best_score

def hex_to_base64(str1):
	return base64.b64encode(bytes.fromhex(str1)).decode()

def hex_to_bytes(str1):
	return bytes.fromhex(str1)

def fixedlen_xor(input1, input2):
	if type(input1) == bytes or type(input1) == bytearray:
		assert(len(input1) == len(input2))
		return bytes([input1[i] ^ input2[i] for i in range(len(input1))])
	elif type(input1) == str:
		assert(len(input1) == len(input2))
		tmp = ""
		for index in range(len(input1)):
			tmp += str(int(input1[index]) ^ int(input2[index]))
		return tmp
	else:
		return input1 ^ input2

def shortest_xor(input1, input2):
	if len(input1) <= len(input2):
		return bytes([input1[i] ^ input2[i] for i in range(len(input1))])
	else:
		return bytes([input1[i] ^ input2[i] for i in range(len(input2))])


def repetting_xor(rep, input2):
	rep = rep * (len(input2) // len(rep) + 1)
	return bytes([rep[i] ^ input2[i] for i in range(len(input2))])

def int_to_bytes(i_data, be=True):
	if be:
		return (i_data).to_bytes((i_data.bit_length() + 7) // 8, byteorder='big')
	else:
		return (i_data).to_bytes((i_data.bit_length() + 7) // 8, byteorder='little')

def bytes_to_int(i_data, be=True):
	#print(type(i_data))
	if be:
		return int.from_bytes(i_data, 'big')
	else:
		return int.from_bytes(i_data, 'little')

def int_to_bytes_length(i_data, length, be=True):
	if be:
		return (i_data).to_bytes(length, byteorder='big')
	else:
		return (i_data).to_bytes(length, byteorder='little')

def bytes_to_bits(bytes1):
	return bin(int.from_bytes(bytes1, 'big'))

def to_blocks(list1, size):
	#print(list1)
	return [list1[i:i + size] for i in range(0, len(list1), size)]

def hamming_distance(bytes1, bytes2):
	distance = 0
	bits1 = bytes_to_bits(bytes1)
	bits2 = bytes_to_bits(bytes2)
	length = min(len(bits1), len(bits2))

	for i in range(length):
		if bits1[i] != bits2[i]:
			distance += 1

	return distance + max(len(bits1), len(bits2)) - length

def avg_hamming_distance(bytes1, block_size):
	distances = []
	prev_block = None

	blocks = to_blocks(bytes1, block_size)
	block_count = len(blocks)

	for index in range(block_size):
		for count in range(block_count-1):
			distance = hamming_distance(blocks[count], blocks[count+1])
			distances.append(distance / len(blocks[count]))

	return sum(distances) / len(distances)

def split_into_blocks(line, key_length):
	return [line[i:i+key_length] for i in range(0, len(line), key_length)]

def add_PKCS7_pad(inputtext, out_length):
	last_block = to_blocks(inputtext, out_length)[-1]
	distance = out_length - len(last_block)
	if distance == 0:
		return bytes(inputtext) + bytes(chr(out_length) * out_length, 'ascii')
	return bytes(inputtext) + bytes(chr(distance) * distance, 'ascii')

def rem_PKCS7_pad(inputtext, out_length):
	last_block = split_into_blocks(inputtext, out_length)[-1]
	padding = last_block[-1]

	# Check if the padding is valid first
	if padding > out_length:
		raise PaddingError("Invalid PKCS#7 padding for given block size")

	# Return the data minus the padding characters
	if last_block[-padding:] == bytes([padding]) * padding:
		#print(inputtext[:-out_length])
		return inputtext[:-out_length] +  last_block[:out_length-padding]

	raise PaddingError("Invalid PKCS#7 padding")


def combind_blocks(blocks):
	return b"".join(blocks)

def shift_rotate_left(number, shift, bits=32): 
	return ((number << shift)|(number >> (bits - shift))) & (2 **(bits) -1)

def shift_rotate_right(number, shift, bits=32): 
	return ((number >> shift)|(number << (bits - shift))) & (2 **(bits) -1)

def bit_not(number, bits=32): 
	return number ^ (2 **(bits) -1)

def asint32(i):
	return i & 0xFFFFFFFF

def asint64(i):
	return i & 0xFFFFFFFFFFFFFFFF

def asint(i, bits=32):
	return i & (2 **(bits) -1)

def bytes_to_intarray(bytestring, byte_length, byte_order="little"):
	ret = []
	for i in range(0, len(bytestring), byte_length):
		c = bytestring[i: i+byte_length]
		ret.append(int.from_bytes(c, byte_order))

	return ret

def intarray_to_bytes(intarray, byte_length, byte_order="little"):
	ret = b""
	for i in range(0, len(intarray)):
		ret += (intarray[i]).to_bytes(byte_length, byteorder=byte_order)

	return ret

def rabinMiller(possible_prime):
	exp = possible_prime - 1
	t = 0
	while exp & 1 == 0:
		exp = exp//2
		t +=1

	for k in range(0,128,2):
		test_number = random.randrange(2, possible_prime-1)
		#a^s is computationally infeasible.  we need a more intelligent approach
		#v = (a**s)%n
		#python's core math module can do modular exponentiation
		mod_prime = pow(test_number, exp, possible_prime) #where values are (num,exp,mod)
		if mod_prime != 1:
			i=0
			while mod_prime != (possible_prime-1):
				if i == test_number-1:
					return False
				else:
					i = i+1
					mod_prime = pow(mod_prime, 2, possible_prime)
	return True

def is_prime(possible_prime):
	#lowPrimes is all primes (sans 2, which is covered by the bitwise and operator)
	#under 1000. taking n modulo each lowPrime allows us to remove a huge chunk
	#of composite numbers from our potential pool without resorting to Rabin-Miller
	lowPrimes = [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97
				,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179
				,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269
				,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367
				,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461
				,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571
				,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661
				,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773
				,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883
				,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997]
	#Check If even
	if (possible_prime & 1 != 0):
		#Check primes under 1000
		for p in lowPrimes:
			if p == possible_prime:
				return True
			elif (possible_prime % p == 0):
				return False
		#Check rabinMiller
		return rabinMiller(possible_prime)
	return False

def generate_probable_prime(bits=1024):
	print("Generating a probable prime with {} bits".format(bits))

	#Maximum number of attempts to get a prime number
	max_attempts = int(100 * (math.log(bits, 2) + 1))

	for x in range(max_attempts):
		#Get X bytes of random data
		#And Convert into an integer
		random_int = int.from_bytes(os.urandom(bits // 8), "big")  

		#Set the Highest bit of the random int
		random_int |= (1 << bits)
		print("-", end="", flush=True)

		#Check if is prime
		if is_prime(random_int):
			return random_int
	raise Exception("Could not generate Prime")

def int_byte_length(i):
	return (i.bit_length() + 7) // 8


def secure_rand_between(bottom, top):
	sys_random = random.SystemRandom()

	if top >= 0:
		rand_int = sys_random._randbelow(top)

		while rand_int < bottom:
			rand_int = sys_random._randbelow(top)

		return rand_int


def bXXencode(b, count=58):
	n = int.from_bytes(b, 'big')
	chars = []
	while n:
		n, i = divmod(n, count)
		chars.append(b58alphabet[i])
	# special case handle the leading 0 bytes... ¯\_(ツ)_/¯
	num_leading_zeros = len(b) - len(b.lstrip(b'\x00'))
	res = num_leading_zeros * b58alphabet[0] + ''.join(reversed(chars))
	return res
