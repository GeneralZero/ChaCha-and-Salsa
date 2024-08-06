from cryptopals_lib import *

class ripemd():
	"""docstring for ripemd"""
	def __init__(self):
		self.state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
		self.buffer_indexes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
							   7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
							   3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
							   1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
							   4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13,
							   5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
							   6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
							   15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
							   8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
							   12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]

		self.rotate_index = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
							 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
							 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
							 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
							 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6,
							 8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
							 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
							 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
							 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
							 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]

		self.round_varables = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E,
							   0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

		self.block_size = 64

		self.message_end = 0x80


	def _set_message(self, message):
		# Convert to bytes if not already
		byte_message = bytearray(message)

		# Get Length shifted by 8 and limit to 64bit int
		input_length_data = len(byte_message)

		# Append 0x80 to the end of the message as a end of message byte
		byte_message.append(self.message_end)

		# Pad the data until the number of bits are equal devisable by the rate.
		# Not including the 8 bytes for the length added at the end
		while (len(byte_message) + 8) % self.block_size != 0:
			byte_message.append(0x00)

		# Append the length data to the message. But first convert to bits
		byte_message += int_to_bytes_length(input_length_data << 3, 8, False)
		# Convert to the number of bits

		return byte_message

	def hash(self, message):
		# Setup message with padding and length data
		byte_message = self._set_message(message)

		# Opperate on each of the block_size 64 bit chunks
		for chunk in to_blocks(byte_message, self.block_size):
			#print(f"Chunk: {chunk}, {len(chunk)}")
			self._hash_message_chunk(chunk)

		# Convert Intagers to Byte string
		return intarray_to_bytes(self.state, 4)

		
	def hash_digest(self, message):
		return self.hash(message).hex()

	def _round_opperation(self, round_idx, temp_buffers, block_buffers):
		round_number = round_idx // 16

		#Round Opperation depends on the Round Number
		if round_number == 0 or round_number == 9:
			#Do round Opperation 
			#Round 1 and 10: x ^ y ^ z
			temp = temp_buffers[0] + (temp_buffers[1] ^ temp_buffers[2] ^ temp_buffers[3]) + self.round_varables[round_number]

		elif round_number == 1 or round_number == 8:
			#Do round Opperations
			#Round 2 and 9: (x & y) | (((~x) % 0x100000000) & z)
			temp = temp_buffers[0] + ((temp_buffers[1] & temp_buffers[2]) | asint32(~temp_buffers[1]) & temp_buffers[3]) + self.round_varables[round_number]

		elif round_number == 2 or round_number == 7:
			#Do round Opperations
			#Round 3 and 8: (x | ((~y) % 0x100000000)) ^ z
			temp = temp_buffers[0] + ((temp_buffers[1] | asint32(~temp_buffers[2])) ^ temp_buffers[3]) + self.round_varables[round_number]

		elif round_number == 3 or round_number == 6:
			#Do round Opperations
			#Round 4 and 7: (x & z) | (((~z) % 0x100000000) & y)
			temp = temp_buffers[0] + ((temp_buffers[1] & temp_buffers[3]) | asint32(~temp_buffers[3]) & temp_buffers[2]) + self.round_varables[round_number]

		elif round_number == 4 or round_number == 5:
			#Do round Opperations
			#Round 5 and 6: x ^ (y | ((~z) % 0x100000000))
			temp = temp_buffers[0] + (temp_buffers[1] ^ (temp_buffers[2] | asint32(~temp_buffers[3]))) + self.round_varables[round_number]

		else:
			raise Exception("Inviald Round")

		#Set the Two buffers
		#print(round_number, temp, block_buffers[self.buffer_indexes[round_idx]] )
		temp_buffers[0] = asint32(shift_rotate_left(asint32(temp + block_buffers[self.buffer_indexes[round_idx]]), self.rotate_index[round_idx]) + temp_buffers[4])
		temp_buffers[2] = shift_rotate_left(temp_buffers[2], 10)

		#Rotate tempbuffers a,b,c,d,e -> e,a,b,c,d
		return [temp_buffers[4], temp_buffers[0], temp_buffers[1], temp_buffers[2], temp_buffers[3]]

	def _hash_message_chunk(self, block):
		#Convert Blocks to 32bit ints
		block_buffers = bytes_to_intarray(block, 4)

		#Clone Internal Buffers
		temp_buffers = self.state[:]

		#Do Inital 5 rounds
		for idx in range(16*5):
			#print(temp_buffers)
			temp_buffers = self._round_opperation(idx, temp_buffers, block_buffers)

		#Safe the Output and reset the temp buffers
		half_round_ouputs = temp_buffers 
		temp_buffers = self.state[:]

		#Do Final 5 rounds
		for idx in range(16*5, 16*10):
			temp_buffers = self._round_opperation(idx, temp_buffers, block_buffers)


		#print(f"state:             {self.state}")
		#print(f"half_round_ouputs: {half_round_ouputs}")
		#print(f"temp_buffers:      {temp_buffers }")
		
		#Set new internal buffers
		temp = asint32(self.state[1] + half_round_ouputs[2] + temp_buffers[3])
		self.state[1] = asint32(self.state[2] + half_round_ouputs[3] + temp_buffers[4])
		self.state[2] = asint32(self.state[3] + half_round_ouputs[4] + temp_buffers[0])
		self.state[3] = asint32(self.state[4] + half_round_ouputs[0] + temp_buffers[1])
		self.state[4] = asint32(self.state[0] + half_round_ouputs[1] + temp_buffers[2])
		self.state[0] = temp

if __name__ == '__main__':
	new = ripemd()

	print(new.hash_digest(b'hello this is a test'))
	#f51960af7dd4813a587ab26388ddab3b28d1f7b4