import base64, math

letter_ranking = b"zqxjkvbpygfwmucldrh snioate"

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

def asint32(i):
	return i & 0xFFFFFFFF

def asint64(i):
	return i & 0xFFFFFFFFFFFFFFFF

def asint(i, bits=32):
	return i & (2 **(bits) -1)

def bytes_to_intarray(bytestring, byte_length, byte_order="little"):
	ret = []
	assert len(bytestring) % (byte_length) == 0
	for i in range(0, len(bytestring), byte_length):
		c = bytestring[i: i+byte_length]
		ret.append(int.from_bytes(c, byte_order))

	return ret

def intarray_to_bytes(intarray, byte_length, byte_order="little"):
	ret = b""
	for i in range(0, len(intarray)):
		ret += (intarray[i]).to_bytes(byte_length, byteorder=byte_order)

	return ret
