from cryptopals_lib import *

class SHA2(object):
	def __init__(self, version=256):
		self.buffers = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
						0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

		self.round_constants = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
								0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
								0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
								0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
								0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
								0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
								0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
								0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
								0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
								0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
								0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
								0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
								0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
								0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
								0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
								0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

		self.output_size = 8
		self.buffer_size = 32

		self.__select_version(version)

	def __select_version(self, version):
		if version == 256:
			return

		elif version == 224:
			self.buffers = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
							0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]
			self.output_size = 7

		else:
			raise ValueError("Invalid SHA2 Version {}".format(self.version))
		
	def _set_message(self, message):
		#Convert to bytes if not already
		byte_message = bytearray(message)

		#Get Length shifted by 8 and limit to 64bit int
		input_length_data = asint64(len(byte_message) << 3)

		#Append 0x80 to the end of the message as a end of message byte
		byte_message.append(0x80)

		#Pad the data to a multable of 64 bytes when the 8 byte input_length_data is added 
		while len(byte_message) % (self.buffer_size * 2) != ((self.buffer_size * 2) - 8):
			byte_message.append(0x00)

		#Append the length data to the message
		byte_message += int_to_bytes_length(input_length_data, 8)

		return byte_message

	def _hash_message_chunk(self, chunk):
		temp_buffers = self.buffers[:]

		#Create the start of the temp chunks
		temp_chunks = bytes_to_intarray(chunk, (self.buffer_size //8), byte_order="big")

		#Generate the rest of the chunks
		for index in range(16, 64):
			temp1 = shift_rotate_right(temp_chunks[index-15], 7) ^ shift_rotate_right(temp_chunks[index-15], 18) ^ (temp_chunks[index-15] >> 3)
			temp2 = shift_rotate_right(temp_chunks[index-2], 17) ^ shift_rotate_right(temp_chunks[index-2], 19) ^ (temp_chunks[index-2] >> 10)
			temp_chunks.append(asint32(temp1 + temp2 + temp_chunks[index-16] + temp_chunks[index-7]))

		#First Rounds itteration
		for round_itteration in range(64):
			#print(round_itteration, temp_buffers)
			#Do Function F (a >>> 2) ^ (a >>> 13) ^ (a >>> 22)
			temp1 = shift_rotate_right(temp_buffers[0], 2) ^ shift_rotate_right(temp_buffers[0], 13) ^ shift_rotate_right(temp_buffers[0], 22)

			#Choose Majority
			#As a bit function (a & b) ^ (a & c) ^ (b & c)
			majority = (temp_buffers[0] & temp_buffers[1]) ^ (temp_buffers[0] & temp_buffers[2]) ^ (temp_buffers[1] & temp_buffers[2])

			#Do Function G (e >>> 6) ^ (e >>> 11) ^ (e >>> 25)
			temp2 = shift_rotate_right(temp_buffers[4], 6) ^ shift_rotate_right(temp_buffers[4], 11) ^ shift_rotate_right(temp_buffers[4], 25)

			#Do Choice
			#As a bit function (e & f) ^ ((~e) & g)
			choice = (temp_buffers[4] & temp_buffers[5]) ^ ((~temp_buffers[4]) & temp_buffers[6])

			#Add get new values
			temp1 = asint32(temp1 + majority)
			temp2 = asint32(temp_buffers[7] + temp2 + choice + self.round_constants[round_itteration] + temp_chunks[round_itteration])

			#Swap and combind values in to the new buffer
			temp_buffers = [asint32(temp1 + temp2), temp_buffers[0], temp_buffers[1], temp_buffers[2],  
							asint32(temp_buffers[3] + temp2), temp_buffers[4], temp_buffers[5], temp_buffers[6]]


		#Chunks are done with the round
		#Update the internal buffers with the new data
		self.buffers = [asint32(self.buffers[0] + temp_buffers[0]), 
						asint32(self.buffers[1] + temp_buffers[1]),
						asint32(self.buffers[2] + temp_buffers[2]),
						asint32(self.buffers[3] + temp_buffers[3]),
						asint32(self.buffers[4] + temp_buffers[4]),
						asint32(self.buffers[5] + temp_buffers[5]),
						asint32(self.buffers[6] + temp_buffers[6]),
						asint32(self.buffers[7] + temp_buffers[7])]


	def hash(self, message):
		#Setup message with padding and length data
		byte_message = self._set_message(message)

		#Opperate on each of the 64 byte chunks
		for chunk in to_blocks(byte_message, (self.buffer_size * 2)):
			self._hash_message_chunk(chunk)

		#Convert Intagers to Byte string
		output = b""
		for x in self.buffers[:self.output_size]:
			output += (x).to_bytes((self.buffer_size // 8), byteorder='big')

		
		return output
		
	def hash_digest(self, message):
		return self.hash(message).hex()

if __name__ == '__main__':
	testsha256 = SHA2()
	testsha224 = SHA2(224)
	print(testsha256.hash_digest(b""))
	#e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	print(testsha224.hash_digest(b""))
	#d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f

	testsha256 = SHA2()
	testsha224 = SHA2(224)
	print(testsha256.hash_digest(b"a"))
	#ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
	print(testsha224.hash_digest(b"a"))
	#abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5

	testsha256 = SHA2()
	testsha224 = SHA2(224)
	print(testsha256.hash_digest(b"c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db"))
	#70887c409868b28117749f9a62a74b962cae287f81cba1a4bb0f48e029a93477
	print(testsha224.hash_digest(b"c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db"))
	#30821b0053bbb3d4fac76e7e33ee40d3c53f8a92910a84e95dcdc8c1
