from cryptopals_lib import *

class SHA512(object):
	def __init__(self, version=512):
		self.buffers = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
						0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]

		self.round_constants = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
								0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
								0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
								0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
								0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
								0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
								0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
								0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
								0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
								0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
								0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
								0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
								0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
								0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
								0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
								0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
								0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
								0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
								0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
								0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

		self.output_size = 8
		self.buffer_size = 64
		self.__select_version(version)

	def __select_version(self, version):
		if version == 512:
			return

		elif version == 384:
			self.buffers = [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
							0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4]
			self.output_size = 6

		else:
			raise ValueError("Invalid SHA512 Version {}".format(self.version))
		
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
		for index in range(16, 80):
			temp1 = shift_rotate_right(temp_chunks[index-15], 1, self.buffer_size) ^ shift_rotate_right(temp_chunks[index-15], 8, self.buffer_size) ^ (temp_chunks[index-15] >> 7)
			temp2 = shift_rotate_right(temp_chunks[index-2], 19, self.buffer_size) ^ shift_rotate_right(temp_chunks[index-2], 61, self.buffer_size) ^ (temp_chunks[index-2] >> 6)
			temp_chunks.append(asint64(temp1 + temp2 + temp_chunks[index-16] + temp_chunks[index-7]))

		#First Rounds itteration
		for round_itteration in range(80):
			#print(round_itteration, temp_buffers)
			#Do Function F (a >>> 2) ^ (a >>> 13) ^ (a >>> 22)
			temp1 = shift_rotate_right(temp_buffers[0], 28, self.buffer_size) ^ shift_rotate_right(temp_buffers[0], 34, self.buffer_size) ^ shift_rotate_right(temp_buffers[0], 39, self.buffer_size)

			#Choose Majority
			#As a bit function (a & b) ^ (a & c) ^ (b & c)
			majority = (temp_buffers[0] & temp_buffers[1]) ^ (temp_buffers[0] & temp_buffers[2]) ^ (temp_buffers[1] & temp_buffers[2])

			#Do Function G (e >>> 6) ^ (e >>> 11) ^ (e >>> 25)
			temp2 = shift_rotate_right(temp_buffers[4], 14, self.buffer_size) ^ shift_rotate_right(temp_buffers[4], 18, self.buffer_size) ^ shift_rotate_right(temp_buffers[4], 41, self.buffer_size)

			#Do Choice
			#As a bit function (e & f) ^ ((~e) & g)
			choice = (temp_buffers[4] & temp_buffers[5]) ^ ((~temp_buffers[4]) & temp_buffers[6])

			#Add get new values
			temp1 = asint64(temp1 + majority)
			temp2 = asint64(temp_buffers[7] + temp2 + choice + self.round_constants[round_itteration] + temp_chunks[round_itteration])

			#Swap and combind values in to the new buffer
			temp_buffers = [asint64(temp1 + temp2), temp_buffers[0], temp_buffers[1], temp_buffers[2],  
							asint64(temp_buffers[3] + temp2), temp_buffers[4], temp_buffers[5], temp_buffers[6]]


		#Chunks are done with the round
		#Update the internal buffers with the new data
		self.buffers = [asint64(self.buffers[0] + temp_buffers[0]), 
						asint64(self.buffers[1] + temp_buffers[1]),
						asint64(self.buffers[2] + temp_buffers[2]),
						asint64(self.buffers[3] + temp_buffers[3]),
						asint64(self.buffers[4] + temp_buffers[4]),
						asint64(self.buffers[5] + temp_buffers[5]),
						asint64(self.buffers[6] + temp_buffers[6]),
						asint64(self.buffers[7] + temp_buffers[7])]


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
	testsha512 = SHA512()
	testsha384 = SHA512(384)
	print(testsha512.hash_digest(b""))
	#cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
	print(testsha384.hash_digest(b""))
	#38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b

	testsha512 = SHA512()
	testsha384 = SHA512(384)
	print(testsha512.hash_digest(b"a"))
	#1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75
	print(testsha384.hash_digest(b"a"))
	#54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31

	testsha512 = SHA512()
	testsha384 = SHA512(384)
	print(testsha512.hash_digest(b"c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db"))
	#23758bdea270ebde88ccb0d69dab03ac9f5d9b80943d25e8c82178568c08754fdbc3a4e3fdfbc85d6afadf4554acde9fbdc1d519cf4be91fee36e6c773a4a536
	print(testsha384.hash_digest(b"c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db"))
	#8ed53db6d1d8e9661126a211d7126af49e9a505144c924b3aab01dbaa9527ab5ef7d1516d30300bdd176d8cce918152e
