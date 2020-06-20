from cryptopals_lib import *

class SHA3(object):
	def __init__(self, version=256, message_delimiter=None, output_size=None):
		# Static Constats
		self.round_constants = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
								0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
								0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
								0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
								0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
								0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008, ]

		self.rotation_constants = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]

		self.column_size = 5
		self.word_size = 64

		# This is a constant derived from the block size.
		# 24 Rounds
		self.rounds = 12 + (2 * int(math.log(self.word_size, 2)))

		# Set the capacity of the algorithum baised on the version
		self.version = version
		self.output_size = (version * 2) // self.word_size
		self.block_size = (self.column_size * self.column_size) - self.output_size

		# Allocate buffers
		self.buffers = [0x00 for x in range(self.column_size * self.column_size)]

		if message_delimiter == None:
			self.message_delimiter = 0x06
		else:
			self.message_delimiter = message_delimiter
			self.version = version * 2
			
	def _set_message(self, message):
		# Convert to bytes if not already
		byte_message = bytearray(message)

		# Get Length shifted by 8 and limit to 64bit int
		input_length_data = len(byte_message)

		# Append 0x80 to the end of the message as a end of message byte
		byte_message.append(self.message_delimiter)

		# Pad the data until the number of bits are equal devisable by the rate.
		while len(byte_message) % (self.block_size * self.word_size // 8) != 0:
			byte_message.append(0x00)

		# Set the last bit to 1
		byte_message[-1] = 0x80

		# Append the length data to the message
		# byte_message += int_to_bytes_length(input_length_data, 8)

		return byte_message

	def __theta(self, buffers):
		parity_column = []

		# Lets pre caluclate the parity columns to be used
		for index in range(self.column_size):
			parity_column.append(buffers[index] ^ buffers[index + self.column_size] ^
								 buffers[index + 2 * self.column_size] ^ buffers[index + 3 * self.column_size] ^
								 buffers[index + 4 * self.column_size])

		# For each 64bit word in the buffer
		for index in range(len(buffers)):
			column_index = index % self.column_size

			# Next Parity shifted by one
			prev_parity_rot = shift_rotate_left(parity_column[(column_index + 1) % self.column_size], 1,
												 self.word_size)

			# Xor the current_word with the previous parity word and the next parity block rotated by one
			# a[i][j] ^= parity(column_index -1) ^ (parity(column_index +1) >>> 1)
			buffers[index] ^= parity_column[(column_index - 1) % self.column_size] ^ prev_parity_rot

		return buffers

	def __rho_phi(self, buffers):
		# This is a combination of the Rho and Phi stages
		# Rho stage is rotate right by a specific number
		# Roate by the rotation_constants
		# Phi stage is to swap the internal indexs

		backup_buffer = buffers[:]

		for index in range(self.column_size * self.column_size):
			# index = x + y*self.column_size
			# new_index = y + ((2*x + 3*y) %5) * self.column_size
			x = index % self.column_size
			y = index // self.column_size
			new_phi_index = y + (((2 * x) + (3 * y)) % self.column_size) * self.column_size

			# Do Rotation and set to the index of the phi stage
			backup_buffer[new_phi_index] = shift_rotate_left(buffers[index], self.rotation_constants[index],
															  self.word_size)

		return backup_buffer

	def __chi(self, buffers):
		# Xor the next element in the row (inversed) and the next element in the row after that
		backup_buffer = buffers[:]

		for index in range(self.column_size * self.column_size):
			x = index % self.column_size
			new_index1 = (index - x) + ((x + 1) % self.column_size)
			new_index2 = (index - x) + ((x + 2) % self.column_size)

			#print()

			# Xor current block with the inverse of the next block with the next block after that
			backup_buffer[index] ^= bit_not(buffers[new_index1], self.word_size) & buffers[new_index2]

		return backup_buffer

	def _hash_message_chunk(self, chunk):
		temp_buffers = self.buffers[:]

		# print([hex(x) for x in temp_buffers])

		# Xor the message and the internal rate buffer
		for index in range(len(chunk)):
			temp_buffers[index] ^= chunk[index]

		# do rounds
		for round_itteration in range(self.rounds):
			#print(f"Step1:", [x for x in temp_buffers])

			# Do Parity xor opperations with columns
			temp_buffers = self.__theta(temp_buffers)
			#print(f"Step2:", [x for x in temp_buffers])

			# Do Rotation and Shift stages
			temp_buffers = self.__rho_phi(temp_buffers)
			#print(f"Step3:", [x for x in temp_buffers])

			# Do Chi Stage
			temp_buffers = self.__chi(temp_buffers)
			#print(f"Step4:", [x for x in temp_buffers])

			# Do Xor Round Constant stage
			# Keccak.RC[i] % (1 << w)
			temp_buffers[0] ^= asint(self.round_constants[round_itteration], self.word_size)
			#print(f"Round {round_itteration}:", [x for x in temp_buffers])

			#return

		self.buffers = temp_buffers

	def hash(self, message):
		# Setup message with padding and length data
		byte_message = self._set_message(message)

		# Opperate on each of the block_size 64 bit chunks
		for chunk in to_blocks(byte_message, (self.block_size * self.word_size // 8), ):
			self._hash_message_chunk(bytes_to_intarray(chunk, (self.word_size // 8)))

		# Convert Intagers to Byte string
		output = b""
		for x in self.buffers:
			output += (x).to_bytes((self.word_size // 8), byteorder='little')

		#To deal with size that is not devisible by the block size
		return output[:(self.version // 8)]

	def hash_digest(self, message):
		return self.hash(message).hex()


if __name__ == '__main__':
	data = b''
	for x in [224, 256, 384, 512]:
		test = SHA3(x)
		print(f"SHA3-{x}(\"\"): {test.hash_digest(data)}")
	#SHA3-224(""): 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7
	#SHA3-256(""): a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
	#SHA3-384(""): 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004
	#SHA3-512(""): a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26

	print()
	data = b'a'
	for x in [224, 256, 384, 512]:
		test = SHA3(x)
		print(f"SHA3-{x}(\"{data.decode()}\"): {test.hash_digest(data)}")
	#SHA3-224("a"): 9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b
	#SHA3-256("a"): 80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b
	#SHA3-384("a"): 1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9
	#SHA3-512("a"): 697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a

	print()
	data = b'a'b"c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db"
	for x in [224, 256, 384, 512]:
		test = SHA3(x)
		print(f"SHA3-{x}(data): {test.hash_digest(data)}")

	#SHA3-224(data): 92028982629a16c3d7cc7f15631e0f8ca6c9ba2af2eef344c4029995
	#SHA3-256(data): 927127b5c9d238e30aaa64b652ce229f42ae89045a80d865b911280d7adbfa97
	#SHA3-384(data): 4f9c960b8f72f09ba9fde734230bf7a2b08aa00393e1425b0940c970467b17158abff23bc471a4df5d27e205564ed502
	#SHA3-512(data): 4d6bc6ce5684f7e38fc65b3fb4833b00aef9992393c11e23004f118f6895b30ebc2661cdd1ab0ebaced960e3c3430848fda0b6d03fc14b11d1d37135ffa3f8e8

	print()
	#SHAKE-128
	test = SHA3(128, 0x1f)
	print(f"SHAKE-128(\"\"): {test.hash_digest(b'')}")
	#SHAKE-128(""): 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26

	#SHAKE-256
	test = SHA3(256, 0x1f)
	print(f"SHAKE-256(\"\"): {test.hash_digest(b'')}")
	#SHAKE-256(""): 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be
