from cryptopals_lib import *

class Blake3Chunk(object):
	"""docstring for Blake3Node"""
	def __init__(self, buffers, flags, blocks_compressed=0, node_number=0):
		#Flags:
		# CHUNK_START         = 0x01
		# CHUNK_END           = 0x02
		# PARENT              = 0x04
		# ROOT                = 0x08
		# KEYED_HASH          = 0x10
		# DERIVE_KEY_CONTEXT  = 0x20
		# DERIVE_KEY_MATERIAL = 0x40
		self.flags = flags

		self.chaining_values = buffers
		self.input_data = b""
		self.blocks_compressed = blocks_compressed
		self.node_number = node_number
		self.max_chunk_size = 1024
		self.max_block_length = 64

		#Compression Settings
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
		self.blake3_permutations = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
		self.rounds = 7
		self.rotations = [16,12,8,7]
		self.blocksize = 32

		#
		self.iv = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
				   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,]

	def len(self):
		return self.max_block_length * self.blocks_compressed + len(self.input_data)

	def _chacha_quarter_round(self, a, b, c, d, message, round_num, index):
		#Calculate indexes from Permuation table and round_index and offset
		message_index  = self.permutations[index]
		constant_index = self.permutations[index+1]

		#Modified first part to include message and round xor
		a = asint((a + b) + message[index], self.blocksize)
		d = asint(d ^ a, self.blocksize)
		d = asint(shift_rotate_right(d, self.rotations[0], self.blocksize), self.blocksize)

		c = asint(c + d, self.blocksize)
		b = asint(b ^ c, self.blocksize)
		b = asint(shift_rotate_right(b, self.rotations[1], self.blocksize), self.blocksize)

		#Modified first part to include message and round xor
		a = asint((a + b) + message[index+1], self.blocksize)
		d = asint(d ^ a, self.blocksize)
		d = asint(shift_rotate_right(d, self.rotations[2], self.blocksize), self.blocksize)

		c = asint(d + c, self.blocksize)
		b = asint(b ^ c, self.blocksize)
		b = asint(shift_rotate_right(b, self.rotations[3], self.blocksize), self.blocksize)

		return [a,b,c,d]

	def _permutation(self, block):
		temp_buffers = block[:]
		for index in range(len(block)):
			#Use the permutation lookup table to get new index
			new_index = self.blake3_permutations[index]
			temp_buffers[index] = block[new_index]

		return temp_buffers

	def _compress_chunk_manual(self, chaining_values, counter, flags, block_length, input_data):
		#Extend inputdata
		if type(input_data) == bytes:
			input_data = input_data.ljust(self.max_block_length, b"\x00")
			input_data = bytes_to_intarray(input_data, (self.blocksize//8), byte_order="little")

		#Check input length
		assert len(input_data) == 16

		'''
		|chainedValue    |chainedValue    |chainedValue   |chainedValue   |
		|chainedValue    |chainedValue    |chainedValue   |chainedValue   |
		|IV              |IV              |IV             |IV             |
		|blockcounter[0] |blockcounter[0] |blocklen       |flags          |
		'''
		#Start setting up the temp buffers
		temp_buffers = chaining_values[:8] + self.iv[:4] + [0,0,0,0]

		#Add the Number of blocks that have been processed
		temp_buffers[12] ^= asint(counter, self.blocksize)
		temp_buffers[13] ^= asint(counter >> self.blocksize, self.blocksize)

		#Add the number of bytes in the current block to be hashed
		temp_buffers[14] = block_length

		temp_buffers[15] = flags

		#print(f"compress: {chaining_values[0]}, {counter}, {flags}, {block_length}, {input_data}")
		#print(f"before: {[hex(x) for x in temp_buffers]}")

		#Do ChaCha rounds with modifications
		for index in range(self.rounds):
			#Do Each Column
			temp_buffers[0], temp_buffers[4], temp_buffers[8],  temp_buffers[12] = self._chacha_quarter_round(temp_buffers[0], temp_buffers[4], temp_buffers[8],  temp_buffers[12], input_data, index, 0)
			temp_buffers[1], temp_buffers[5], temp_buffers[9],  temp_buffers[13] = self._chacha_quarter_round(temp_buffers[1], temp_buffers[5], temp_buffers[9],  temp_buffers[13], input_data, index, 2)
			temp_buffers[2], temp_buffers[6], temp_buffers[10], temp_buffers[14] = self._chacha_quarter_round(temp_buffers[2], temp_buffers[6], temp_buffers[10], temp_buffers[14], input_data, index, 4)
			temp_buffers[3], temp_buffers[7], temp_buffers[11], temp_buffers[15] = self._chacha_quarter_round(temp_buffers[3], temp_buffers[7], temp_buffers[11], temp_buffers[15], input_data, index, 6)
				
			#Do Each Diagonal
			temp_buffers[0], temp_buffers[5], temp_buffers[10], temp_buffers[15] = self._chacha_quarter_round(temp_buffers[0], temp_buffers[5], temp_buffers[10], temp_buffers[15], input_data, index, 8)
			temp_buffers[1], temp_buffers[6], temp_buffers[11], temp_buffers[12] = self._chacha_quarter_round(temp_buffers[1], temp_buffers[6], temp_buffers[11], temp_buffers[12], input_data, index, 10)
			temp_buffers[2], temp_buffers[7], temp_buffers[8],  temp_buffers[13] = self._chacha_quarter_round(temp_buffers[2], temp_buffers[7], temp_buffers[8],  temp_buffers[13], input_data, index, 12)
			temp_buffers[3], temp_buffers[4], temp_buffers[9],  temp_buffers[14] = self._chacha_quarter_round(temp_buffers[3], temp_buffers[4], temp_buffers[9],  temp_buffers[14], input_data, index, 14)

			#Black3 only permuste the input data
			if index != self.rounds - 1:
				input_data = self._permutation(input_data)

		#print(f"after: {[hex(x) for x in temp_buffers]}")

		#Update Buffers
		for x in range(8):
			temp_buffers[x]   ^= temp_buffers[x+8]
			temp_buffers[x+8] ^= chaining_values[x]

		#print(f"done: {[hex(x) for x in temp_buffers]}")

		return temp_buffers



	def _compress_chunk(self, **kwargs):
		#Set defaults
		chaining_values = self.chaining_values
		node_number = self.node_number
		flags = self.flags
		block_length = len(self.input_data)
		input_data = self.input_data

		#Add the flags to the end
		if self.blocks_compressed == 0:
			#Set CHUNK_START flag
			flags |= 0x01
		elif self.blocks_compressed == 16:
			#Set CHUNK_END
			flags |= 0x02

		#Overwride defaults if needed
		for arg in kwargs:
			if arg == "chaining_values":
				chaining_values = kwargs[arg]
			elif arg == "counter":
				node_number = kwargs[arg]
			elif arg == "block_length":
				block_length = kwargs[arg]
			elif arg == "input_data":
				input_data = kwargs[arg]
			elif arg == "flags":
				flags |= kwargs[arg]

		return self._compress_chunk_manual(chaining_values, node_number, flags, block_length, input_data)


	def update(self, byte_input):
		while len(byte_input) > 0:

			#Check if block is currently full
			if len(self.input_data) == self.max_block_length:
				self.chaining_values = self._compress_chunk(flags=self.flags)[:8]

				#Update Compressed
				self.blocks_compressed +=1
				self.input_data = b""

			#Add up to the max_block_length 
			input_length = min(self.max_block_length, self.max_block_length - len(self.input_data))
			self.input_data += byte_input[:input_length]
			byte_input = byte_input[input_length:]


	def output(self):
		#If less than 64 bytes pad data
		data = self.input_data.rjust(self.blocksize * 2, b"\x00")

		#Add the END_CHUNK Flag
		return self._compress_chunk(flags = (self.flags | 0x02))


class Blake3(object):
	def __init__(self, output_size=256, key=None, personalization=None):
		#Blake3 Constants
		#Chunk State Varables
		self.output_size = output_size
		self.blocksize = 32
		self.iv = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
				   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,]

		self.cv_stack = []

		#Blake3 with a custom IV For keyed hashing
		if key != None:
			#If specifying a key it must be 32 bytes to fit into the buffers
			assert len(key) == 32
			self.iv = bytes_to_intarray(key, (self.blocksize//8), byte_order="little")
			self.flags = 0x10

			#Since the key is set the flag for Keyed Hash (16 = 0x10)
			self.chunk = Blake3Chunk(self.iv, self.flags)

		#Blake3 to derive key from personalization
		elif personalization != None:
			#Get the Blake3 Hash of rhe personaliztion message to use for the key.
			#This will be set with the DERIVE_KEY_CONTEXT flag (32 = 0x20)
			derived_key = Blake3()
			derived_key.flags |= 0x20
			derived_key.update(personalization)

			#Set the key to the derived key 
			self.iv = bytes_to_intarray(derived_key.finalize(), (self.blocksize//8), byte_order="little")

			#Set the DERIVE_KEY_MATERIAL flag (64 = 0x40)
			self.flags = 0x40
			self.chunk = Blake3Chunk(self.iv, self.flags)

		else:
			self.flags = 0x00
			self.chunk = Blake3Chunk(self.iv, self.flags)


	def _set_message(self, message):
		#Convert to bytes if not already
		byte_message = bytearray(message)

		#Set Final Length
		self.final_length = len(message)

		#Pad the data to a multable of the block size
		while len(byte_message) == 0 or len(byte_message) % (self.blocksize * 2) != 0:
			byte_message.append(0x00)

		return byte_message

	def append_chunk_cv(self, right_node_cv, chunk_num):

		#Check If new chunk is the first one in the next level
		while chunk_num & 1 == 0:

			#Get the Left Node
			left_node_cv = self.cv_stack.pop()

			#Compress the left and right node with the parrent flag
			right_node_cv = self.chunk._compress_chunk(chaining_values=self.iv, counter=0, block_length=self.chunk.max_block_length, flags=(self.flags | 0x04), input_data=(left_node_cv + right_node_cv))[:8]

			#Move Chunk to the next level to compress
			chunk_num >>= 1

		self.cv_stack.append(right_node_cv)

	def update(self, byte_input):
		#Add Data to Chunks
		while len(byte_input) > 0:

			#Test if chunk reaches max_size then add a new chunk node
			if self.chunk.max_chunk_size == self.chunk.len():
				#Get Chaining Value
				chunk_chaining_value = self.chunk.output()

				#Update and Reset Data
				self.chunk.node_number += 1
				self.chunk.input_data = b""

				#Update Chunk and Check if needs to compress
				self.append_chunk_cv(chunk_chaining_value[:8], self.chunk.node_number)

				#Create New Chunk
				self.chunk = Blake3Chunk(self.iv, self.flags, 0, self.chunk.node_number)

			#Add data to chunk up to the chunk_length
			max_read_bytes = min(self.chunk.max_chunk_size - len(self.chunk.input_data), len(byte_input))

			#Send Buffer to the chunk
			self.chunk.update(byte_input[:max_read_bytes])

			#Remove the Data that was sent to the chunk
			byte_input = byte_input[max_read_bytes:]

	def finalize(self, output_size=32):
		right_data = []
		left_data = bytes_to_intarray(self.chunk.input_data.ljust(self.chunk.max_block_length, b"\x00"), (self.blocksize//8), byte_order="little")
		cv_stack_remaining = len(self.cv_stack)

		#Set the End Flag for the next compress
		self.chunk.flags |= 0x02

		##Compress all Parent Values to a single Value
		while cv_stack_remaining > 0:
			#Decrease Stack Number
			cv_stack_remaining -= 1

			#Set the Parent Flag globaly until the end
			self.flags |= 0x04

			#Get Current Chaining Value
			if right_data == []:
				#If is the first time get the output
				right_data = self.chunk.output()[:8]
			else:
				right_data = self.chunk._compress_chunk(chaining_values=self.iv, counter=0, block_length=self.chunk.max_block_length, flags=self.flags, input_data=(left_data + right_data))[:8]
			#Setup the next Chain
			left_data = self.cv_stack[cv_stack_remaining]
			self.chunk = Blake3Chunk(self.iv, self.flags, 1, 0)
		
		#Do Final Compress from the root
		i = 0
		ret = []
		while (len(ret) * 4) < output_size:
			if right_data == []:
				#Set the ROOT Flag
				ret += self.chunk._compress_chunk(counter=i, flags=(self.flags | 0x08), block_length=len(self.chunk.input_data), input_data=(left_data + right_data)
				)
			else:
				ret += self.chunk._compress_chunk(counter=i, flags=(self.flags | 0x08), block_length=self.chunk.max_block_length, input_data=(left_data[:8] + right_data)
				)

			i += 1
		return intarray_to_bytes(ret, (self.blocksize//8), byte_order="little")[:output_size]

	def hash_digest(self, message, output_size=32):
		return self.hash(message, output_size).hex()

if __name__ == '__main__':
	#messages = [b"TESTDATA", b"TESTDATA" *10, b"TESTDATA" * 200] #b"TESTDATA" * 1000
	messages = [b"TESTDATA" * 1000]

	for message in messages:
		#blake3 = Blake3(key=b"\xBB\x67\xAE\x85"*8)
		#blake3 = Blake3(personalization=b"pure_blake3 2021-10-29 18:37:44 example context")
		blake3 = Blake3()

		blake3.update(message)

		#print(f"blake3.finalize()")
		output = blake3.finalize()
		print(f"{message}: {output.hex()}")
