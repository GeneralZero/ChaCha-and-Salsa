import sys
sys.path.append("..")

from cryptopals_lib import *

def key_schedule(input_key):
	key_len = len(input_key)

	#Initalize Key with values from 0-255
	s_box = [x for x in range(256)]

	swap_index = 0
	for index in range(256):
		#Choose second index to swap values of
		swap_index += s_box[index] + input_key[index % key_len]
		swap_index %= 256

		#Swap the index I with the acc index
		s_box[swap_index], s_box[index] = s_box[index], s_box[swap_index]

	return s_box

def psudo_random_generator(s_box):
	index = 0 
	i = 0 

	while True:
		#Increase the Index
		index += 1 
		index %= 256

		#Choose second index to swap values of
		i += s_box[index]
		i %= 256

		#Swap values of the specified indexes
		s_box[index], s_box[i] = s_box[i], s_box[index]

		#Output the byte from the calculated index
		output_index = (s_box[index] + s_box[i]) % 256
		yield s_box[output_index]

def RC4(key):
	#Generate the s_box from the secret key
	s_box = key_schedule(key)

	#Generate Keystream from s_box
	return psudo_random_generator(s_box)


if __name__ == '__main__':
	#Test Vectors from https://tools.ietf.org/html/rfc6229

	key_stream = RC4(bytes_to_intarray(b"\x01\x02\x03\x04\x05", 1))

	output_data = b""
	for _ in range(32):
		output_data += int_to_bytes(next(key_stream))
	print(output_data.hex())

	assert(output_data.hex() == "b2396305f03dc027ccc3524a0a1118a86982944f18fc82d589c403a47a0d0919")
