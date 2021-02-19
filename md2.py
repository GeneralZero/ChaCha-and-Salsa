from cryptopals_lib import *

class MD2(object):
	def __init__(self):
		self.block_size = 16
		self.buffer_size = 48
		self.round_count = 18
		self.buffer = bytearray([0 for _ in range(self.buffer_size)])

		self.sbox = [41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
					19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
					76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
					138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
					245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
					148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
					39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
					181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
					150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
					112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
					96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
					85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
					234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
					129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
					8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
					203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
					166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
					31, 26, 219, 153, 141, 51, 159, 17, 131, 20]

	def _set_message(self, message):
		#Convert to bytes if not already
		byte_message = bytearray(message)

		#Get Padding Number
		padding_number = self.block_size - (len(message) % self.block_size)

		#Add the padding number to pad the input to the next block
		for _ in range(padding_number):
			byte_message.append(padding_number)

		#Append Checksum
		checksum_byte = 0
		checksum = bytearray(0 for _ in range(self.block_size))

		# For each Block
		for block_num, block in enumerate(to_blocks(byte_message, self.block_size)):

			# Calculate checksum of block using each byte of the block
			for byte_num, byte in enumerate(block):
				checksum_byte = self.sbox[byte ^ checksum_byte]
				checksum[byte_num] = checksum_byte

		byte_message += checksum

		return byte_message

	def _hash_message_chunk(self, chunk):
		for bit_index, bit in enumerate(chunk):
			self.buffer[self.block_size + bit_index] = bit
			self.buffer[2 * self.block_size + bit_index] = self.buffer[self.block_size + bit_index] ^ self.buffer[bit_index]

		#print(self.buffer)

		# Rounds of encryption over the entire array. Current byte XOR'd with the previous (substituted) byte.
		hash_byte = 0
		for round_num in range(self.round_count):
			for bit_index in range(self.buffer_size):
				#print(self.buffer)
				hash_byte = self.buffer[bit_index] ^ self.sbox[hash_byte]
				self.buffer[bit_index] = hash_byte

			hash_byte = (hash_byte + round_num) % len(self.sbox)


	def hash(self, message):
		#Setup message with padding and length data
		byte_message = self._set_message(message)

		#Opperate on each of the 64 byte chunks
		for chunk in to_blocks(byte_message, self.block_size):
			self._hash_message_chunk(chunk)

		#Convert Intagers to Byte string
		return self.buffer[:16]
		
	def hash_digest(self, message):
		return self.hash(message).hex()

if __name__ == '__main__':
	testmd2 = MD2()
	print(testmd2.hash_digest(b""))
	#8350e5a3e24c153df2275c9f80692773
	#8350e5a3e24c153df2275c9f80692773

	testmd2 = MD2()
	print(testmd2.hash_digest(b"a"))
	#32ec01ec4a6dac72c0ab96fb34c0b5d1
	#32ec01ec4a6dac72c0ab96fb34c0b5d1

	testmd2 = MD2()
	print(testmd2.hash_digest(b"c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db"))
	#552a74992714b647a8f06a77e24dec6b
	#552a74992714b647a8f06a77e24dec6b
