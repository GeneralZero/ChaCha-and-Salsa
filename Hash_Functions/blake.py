import sys
sys.path.append("..")

from cryptopals_lib import *

class Blake(object):
	def __init__(self, version=512):
		self.round_constant1 = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
								0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
								0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
								0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,]


		self.round_constant2 = [0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0, 0x082EFA98EC4E6C89,
								0x452821E638D01377, 0xBE5466CF34E90C6C, 0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
								0x9216D5D98979FB1B, 0xD1310BA698DFB5AC, 0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
								0xBA7C9045F12C7F99, 0x24A19947B3916CF7, 0x0801F2E2858EFC16, 0x636920D871574E69,]

		self.permutations = [
			[ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15],
			[14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3],
			[11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4],
			[ 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8],
			[ 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13],
			[ 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9],
			[12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11],
			[13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10],
			[ 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5],
			[10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0],
			[ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15],
			[14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3],
			[11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4],
			[ 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8],
			[ 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13],
			[ 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9],
			[12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11],
			[13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10],
			[ 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5],
			[10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0],
		]
		self.salt = [0x00, 0x00, 0x00, 0x00]
		self.xor_block = True
		self.current_length = 0
		self.__select_version(version)

	def __select_version(self, version):
		if version == 224:
			self.buffers = [0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
							0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,]

			self.round_constants = self.round_constant1
			self.rotations = [16,12,8,7]
			self.blocksize = 32
			self.rounds = 14
			self.padding_end = 0x00
			self.output_size = 7

		elif version == 256:
			self.buffers = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
							0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,]

			self.round_constants = self.round_constant1
			self.rotations = [16,12,8,7]
			self.blocksize = 32
			self.rounds = 14
			self.padding_end = 0x01
			self.output_size = 8
			        
		elif version == 384:
			self.buffers = [0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
							0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,]

			self.round_constants = self.round_constant2
			self.output_size = 6
			self.rotations = [32,25,16,11]
			self.blocksize = 64
			self.rounds = 16
			self.padding_end = 0x00
			self.output_size = 6

		elif version == 512:
			self.buffers = [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
							0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,]
			self.round_constants = self.round_constant2
			self.rotations = [32,25,16,11]
			self.blocksize = 64
			self.rounds = 16
			self.padding_end = 0x01
			self.output_size = 8

		else:
			raise ValueError("Invalid Blake Version {}".format(self.version))
		
	def _set_message(self, message):
		#Convert to bytes if not already
		byte_message = bytearray(message)

		#Append 0x80 to the end of the message
		byte_message.append(0x80)

		#Get Length shifted by 8 and limit to int
		self.final_length = len(message) << 3
		input_length_data = asint(self.final_length, self.blocksize * 2)

		#Pad the data to a multable of 64 bytes when the 8 byte input_length_data is added 
		while len(byte_message) % (self.blocksize * 2) != ((self.blocksize * 2) - ((self.blocksize * 2) // 8)):
			byte_message.append(0x00)

		#Make the last byte of the padding end with a 1 or a 0 depending on the hash version
		byte_message[-1] |= self.padding_end

		#Append the length data to the message
		byte_message += int_to_bytes_length(input_length_data, (self.blocksize * 2) // 8 )

		return byte_message

	def _chacha_quarter_round(self, a, b, c, d, message, round_num, index):
		#Calculate indexes from Permuation table and round_index and offset
		message_index  = self.permutations[round_num][index]
		constant_index = self.permutations[round_num][index+1]

		#Modified first part to include message and round xor
		a = asint((a + b) + (message[message_index] ^ self.round_constants[constant_index]), self.blocksize)
		d = asint(d ^ a, self.blocksize)
		d = asint(shift_rotate_right(d, self.rotations[0], self.blocksize), self.blocksize)

		c = asint(c + d, self.blocksize)
		b = asint(b ^ c, self.blocksize)
		b = asint(shift_rotate_right(b, self.rotations[1], self.blocksize), self.blocksize)

		#Modified first part to include message and round xor
		a = asint((a + b) + (message[constant_index] ^ self.round_constants[message_index]), self.blocksize)
		d = asint(d ^ a, self.blocksize)
		d = asint(shift_rotate_right(d, self.rotations[2], self.blocksize), self.blocksize)

		c = asint(d + c, self.blocksize)
		b = asint(b ^ c, self.blocksize)
		b = asint(shift_rotate_right(b, self.rotations[3], self.blocksize), self.blocksize)

		return [a,b,c,d]


	def _compress_chunk(self, chunk):
		#Start the compress function

		#Create the start of the temp chunks
		temp_chunk = bytes_to_intarray(chunk, (self.blocksize //8), byte_order="big")
		#print(f"message: {[hex(x) for x in temp_chunk]}")

		#Start setting up the temp buffers
		temp_buffers = self.buffers[:] + self.round_constants[:8]

		for x in range(4):
			temp_buffers[8+x] ^= self.salt[x]

		#Do not xor currentlength when it is the last block and there is more than one block
		if self.xor_block:
			temp_buffers[12] ^= asint(self.current_length, self.blocksize)
			temp_buffers[13] ^= asint(self.current_length, self.blocksize)
			temp_buffers[14] ^= (self.current_length >> self.blocksize)
			temp_buffers[15] ^= (self.current_length >> self.blocksize)

		'''
		Resulting temp_buffers looks like this
		|IV             |IV             |IV              |IV              |
		|IV             |IV             |IV              |IV              |
		|Const ^ Salt   |Const ^ Salt   |Const ^ Salt    |Const ^ Salt    |
		|Const ^ len[0] |Const ^ len[0] |Const ^ len[1]  |Const ^ len[1]  |
		'''
		#print([hex(x) for x in temp_buffers[12:]], not self.xor_block, hex(self.current_length))

		#Do ChaCha rounds with modifications
		for index in range(self.rounds):
			#Do Each Column
			temp_buffers[0], temp_buffers[4], temp_buffers[8],  temp_buffers[12] = self._chacha_quarter_round(temp_buffers[0], temp_buffers[4], temp_buffers[8],  temp_buffers[12], temp_chunk, index, 0)
			temp_buffers[1], temp_buffers[5], temp_buffers[9],  temp_buffers[13] = self._chacha_quarter_round(temp_buffers[1], temp_buffers[5], temp_buffers[9],  temp_buffers[13], temp_chunk, index, 2)
			temp_buffers[2], temp_buffers[6], temp_buffers[10], temp_buffers[14] = self._chacha_quarter_round(temp_buffers[2], temp_buffers[6], temp_buffers[10], temp_buffers[14], temp_chunk, index, 4)
			temp_buffers[3], temp_buffers[7], temp_buffers[11], temp_buffers[15] = self._chacha_quarter_round(temp_buffers[3], temp_buffers[7], temp_buffers[11], temp_buffers[15], temp_chunk, index, 6)
				
			#Do Each Diagonal
			temp_buffers[0], temp_buffers[5], temp_buffers[10], temp_buffers[15] = self._chacha_quarter_round(temp_buffers[0], temp_buffers[5], temp_buffers[10], temp_buffers[15], temp_chunk, index, 8)
			temp_buffers[1], temp_buffers[6], temp_buffers[11], temp_buffers[12] = self._chacha_quarter_round(temp_buffers[1], temp_buffers[6], temp_buffers[11], temp_buffers[12], temp_chunk, index, 10)
			temp_buffers[2], temp_buffers[7], temp_buffers[8],  temp_buffers[13] = self._chacha_quarter_round(temp_buffers[2], temp_buffers[7], temp_buffers[8],  temp_buffers[13], temp_chunk, index, 12)
			temp_buffers[3], temp_buffers[4], temp_buffers[9],  temp_buffers[14] = self._chacha_quarter_round(temp_buffers[3], temp_buffers[4], temp_buffers[9],  temp_buffers[14], temp_chunk, index, 14)
			#print(f"After Round {index} {temp_buffers}")

		#Update Buffers
		for x in range(8):
			#print(self.buffers[x], temp_buffers[x], temp_buffers[x+8], self.salt[x % 4])
			self.buffers[x] ^= (temp_buffers[x] ^ temp_buffers[x+8] ^ self.salt[x % 4])

		#print(self.buffers)

	def hash(self, message):
		#Setup message with padding and length data
		byte_message = self._set_message(message)

		#Opperate on each of the chunks
		blocks = to_blocks(byte_message, (self.blocksize * 2))
		#print(blocks)

		for index, chunk in enumerate(blocks):

			#Fix Edge Case for padding goes into the next block
			if index == len(blocks) - 1:
				#Calculate the last block size without padding
				mod_num = (self.final_length >> 3) % (self.blocksize * 2)
				#print(mod_num, (self.blocksize * 2) - ((self.blocksize * 2) // 8)-1, (self.blocksize * 2))

				#If adding the padding would make a new block the last block
				# If mod_num is inbetween 55-64 then 
				if (mod_num > (self.blocksize * 2) - ((self.blocksize * 2) // 8) - 1 and mod_num <= (self.blocksize * 2)):
					self.current_length = self.final_length - ((self.blocksize * 2) // 8)
					self.xor_block = False
				elif mod_num == 0:
					self.xor_block = False
				else:
					self.current_length = self.final_length 
				

			#Fix Edge Case for padding goes into the next block
			elif (self.current_length + (len(chunk) << 3)) >= self.final_length:
				self.current_length = self.final_length

			else:
				#Update the current_length
				self.current_length += (len(chunk) << 3)

			#print(self.current_length, self.final_length)
			#Compress the message Chunk
			self._compress_chunk(chunk)

		#Convert Intagers to Byte string
		output = b""
		for x in self.buffers[:self.output_size]:
			output += (x).to_bytes((self.blocksize // 8), byteorder='big')

		return output
		
	def hash_digest(self, message):
		return self.hash(message).hex()

if __name__ == '__main__':

	testcases = [b"", b"a", b'a' * 57, 
	b"c840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db", 
	b"c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db"]

	for version in [224, 256, 384, 512]:
		print(f"Starting Blake({version})")
		for index, input_value in enumerate(testcases):
			test = Blake(version)
			print(f"Blake{version}[{input_value}] = {test.hash_digest(input_value)}")
		print()

	"""
	Starting Blake(224)
	Blake224[b''] = 7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed
	Blake224[b'a'] = ee2a38e73954cc635cef43dba65e7ee9f5673884851fd70963284940
	Blake224[b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] = 83973600cf2e63fc8296a243720d95b38328289a7536110b4b403a1f
	Blake224[b'c840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db'] = 3cdbe0625207fc16733131ae913b4e3231e578a67b05079957730e40
	Blake224[b'c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db'] = 77eb15b3b2df810211655c5b5c13bcd9dabb369f782ab0b97d914be9

	Starting Blake(256)
	Blake256[b''] = 716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a
	Blake256[b'a'] = 43234ff894a9c0590d0246cfc574eb781a80958b01d7a2fa1ac73c673ba5e311
	Blake256[b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] = ce22e4ab7c77d095f22688612e517af0f4b2c68ab59ac7fcebd2b73c6ee931ed
	Blake256[b'c840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db'] = 3cb9ba4655cc30f6c8fe982f2337f38e221eb8d38c1dce2e0a07d1e09846bfab
	Blake256[b'c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db'] = c1f88698b4881f2e568ceed1f71788e6ea9ecdbf06aa2c74acf4e15e19cb9760

	Starting Blake(384)
	Blake384[b''] = c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706
	Blake384[b'a'] = 43b10bdc1b8b623050d47529d48a44fae16023f93596d0307e99a6b4299891cf639fd2673c97ce4062df1068be3f827e
	Blake384[b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] = a8efcb6d6b5f338069672ebd82a2b756947a0fd4c6c82f2f4358620f304583a518b2eb5f1c425d0b0bcea7c49205164f
	Blake384[b'c840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db'] = 02a610974367ea88e6236b9d09ec1d4286ae5d05859629970bae6050148502a7042b40414ac2d7376d8b1679ec149388
	Blake384[b'c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db'] = fa9bd0416ad04b11ae1142e1d9b56c8345f4ad8f4260c16aa3f2116551726d91b5a2eb74143ed6c25512151751a94c4f

	Starting Blake(512)
	Blake512[b''] = a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8
	Blake512[b'a'] = 780fca7981665e2dc073ad3e64699401a8503d62a18742ad5de7c42bf2cf269a1805df497d4e8b148d91a04a6128986ce4e4d29fb97952446868b2f5d915d9e5
	Blake512[b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] = f0aac1c949e2b80a5639938be5a2853c068da11d8b7a6b9a1810c43e54e4ca9f24ee326621453fb5c413e0a462960daa8111216be70df8c327e075c55b62665e
	Blake512[b'c840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db'] = cda050847c9c205d98f1ed456047e7eff1bda5f649012ccaa001bc72cf22bc1e643ef8f501c50e8a9cd8af32a5ad34f2e0c3d32c7fe8ee7f36c913c40091c5df
	Blake512[b'c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db'] = 7775bb38e63f209927654a3abdf48e24dc945f4b3e746703c7b1c33a9669ac6014ace5495bdc8ef989657c36aef29f59c8ed8a69983c28e50b1115e903303a99
	"""
