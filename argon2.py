import builtins
from cryptopals_lib import *
from blake2 import Blake2

class Argon2(object):
	def __init__(self, time_cost, parallelism, memory_cost, tag_length=32):
		#Start sanity checks so that there is no index errors
		if (memory_cost >> 3) < parallelism:
			raise Exception("Memory Cost must be atleat 8 time more than Parallelism cost")

		self.parallelism = parallelism
		self.memory_cost = memory_cost
		self.time_cost = time_cost
		self.tag_length = tag_length
		self.rotations = [32,24,16,63]
		self.blocksize = 64

		#Use the newest version of Argon2. This can be 0x10 and will only effect one line of code
		self.argon_version = 0x13
		#Set default to false and change if Argon2i or Argon2id is called
		self.data_dependant = False

		#Derive Values from memory cost and parallelism cost
		self.block_count = (self.memory_cost // (self.parallelism << 2) ) * (self.parallelism << 2)
		self.column_count = self.block_count // self.parallelism
		self.segment_length = self.column_count >> 2

		#Allocate the matrix of size column_count x self.parallelism
		self.internal_buffer = [[b"" for j in range(self.column_count)] for i in range(self.parallelism)]

	def _init_buffer(self, hash_type, message, salt, optional_key=b'', associated_data=b''):
		#Initalize blake2b-512
		#Set Hash type for later opperations
		self.hash_type = hash_type

		#Initalize the inital buffer using the blake2 algorithum with the options of the hash
		# parallelism | tag_length | memory_cost | time_cost | argon_version | hash_type | len(password) | password | len(salt) | salt | len(secret) | secret | len(secret) | associated_data
		blake_input =  int_to_bytes_length(self.parallelism, 4, False)
		blake_input += int_to_bytes_length(self.tag_length, 4, False)
		blake_input += int_to_bytes_length(self.memory_cost, 4, False)
		blake_input += int_to_bytes_length(self.time_cost, 4, False)
		blake_input += int_to_bytes_length(self.argon_version, 4, False)
		blake_input += int_to_bytes_length(self.hash_type, 4, False)

		#Also add the lengths and inputs to the inital blake2 input
		blake_input += int_to_bytes_length(len(message), 4, False)
		blake_input += message
		blake_input += int_to_bytes_length(len(salt), 4, False)
		blake_input += salt
		blake_input += int_to_bytes_length(len(optional_key), 4, False)
		blake_input += optional_key
		blake_input += int_to_bytes_length(len(associated_data), 4, False)
		blake_input += associated_data

		#Use Blake2-512 to initalize the buffer that will be used as input for the first few rounds
		self.inital_buffer = hex_to_bytes(Blake2(512).hash_digest(blake_input))

	def hash2d(self, message, salt, optional_key=b'', associated_data=b''):
		#Set type_code to 0 for Argon2d
		self._init_buffer(0, message, salt, optional_key, associated_data)

		return self._do_loops()

	def hash2i(self, message, salt, optional_key=b'', associated_data=b''):
		#Set type_code to 1 for Argon2i
		self._init_buffer(1, message, salt, optional_key, associated_data)

		#Argon2i is data dependant
		self.data_dependant = True

		return self._do_loops()

	def hash2id(self, message, salt, optional_key=b'', associated_data=b''):
		#Set type_code to 2 for Argon2id
		self._init_buffer(2, message, salt, optional_key, associated_data)

		#Argon2id is data dependant
		self.data_dependant = True

		return self._do_loops()

	def _do_loops(self):
		#Loop through the diffrent indexes 
		for time_idx in range(self.time_cost):
			for segment_idx in range(4):
				#initalize buffers for each (fake) parellel process
				segment_buffers = [] 
				
				#For Each paralel and save them to be added to the internal buffer
				for par_idx in range(self.parallelism):
					segment_buffers.append(self.fill_segments(time_idx, segment_idx, par_idx))

				#Combine the segments together with correct indexes
				for par_idx in range(len(segment_buffers)):
					for index in range(len(segment_buffers[par_idx])):
						self.internal_buffer[par_idx][segment_idx * self.segment_length + index] = segment_buffers[par_idx][index]

		output = b"\x00" * 1024

		#Finalize the output with 1024 length xors
		for par_idx in range(self.parallelism):
			output = fixedlen_xor(output, self.internal_buffer[par_idx][self.column_count-1])
		
		#Do a final Blake2 Varable Hash with the output and the final target tag length
		return self._blake2_varable_hash(output, self.tag_length)

	def _blake2_varable_hash(self, message, digest_size):
		""" This is a varable length Hash function that is baised on blake2"""
		# Prepend the length of the message to prevent length extention like attacks
		input_data = int_to_bytes_length(digest_size, 4, False)
		input_data += message
		
		#if the size is small enough then just use a single blake2 output 
		if digest_size <= 512:
			return hex_to_bytes(Blake2(512, output_size=digest_size).hash_digest(input_data))
		else:
			#If the output size is greater than the output of Blake2 get the first 32 bytes of the output rehash and append.
			digest_output = hex_to_bytes(Blake2(512).hash_digest(input_data))
			#Take the first 32 bytes of data
			output = digest_output[:32]

			#Continue hashing the full digest_output and appending the first 32 bytes to the output.
			while digest_size - len(output) > 64:
				digest_output = hex_to_bytes(Blake2(512).hash_digest(digest_output))

				#Add the Hash output and rehash again
				output += digest_output[:32]

			#Finish the output by specifying the leftover size to the Blake algorithum
			output += hex_to_bytes(Blake2(512, output_size=digest_size - len(output)).hash_digest(digest_output))

			return output

	def fill_segments(self, time_idx, segment_idx, par_idx):
		#Initalize the pseudo_rands if it is argon2i or argon2id. (The I stands for indepent)
		if self.data_dependant:
			pseudo_rands = []

			#Initalize the pseudo_rands with some random data generated by the paramaters
			idx = 1
			while len(pseudo_rands) < self.segment_length:
				# Make 1024 input block with 8 byte for each intager information
				input_data = int_to_bytes_length(time_idx, 8, False)
				input_data += int_to_bytes_length(par_idx, 8, False)
				input_data += int_to_bytes_length(segment_idx, 8, False)
				input_data += int_to_bytes_length(self.block_count, 8, False)
				input_data += int_to_bytes_length(self.time_cost, 8, False)
				input_data += int_to_bytes_length(self.hash_type, 8, False)
				input_data += int_to_bytes_length(idx, 8, False)
				#Pad the rest of the input with null bytes
				input_data += b'\0' * (1024 - len(input_data))

				#Send it to the compression algorithum twice
				input_data = self._chacha_compress(b'\0'*1024, input_data)
				input_data = self._chacha_compress(b'\0'*1024, input_data)

				#Convert the byte string to 4 byte intagers
				pseudo_rands += bytes_to_intarray(input_data, 4)
				idx += 1

		for idx in range(self.segment_length):
			buffer_idx = (segment_idx * self.segment_length) + idx

			#A special first case to initalize the first two internal buffers
			if time_idx == 0 and buffer_idx < 2:
				#Use the INITAL BUFFER derived from argon2 input data
				temp = self.inital_buffer + int_to_bytes_length(buffer_idx, 4, False) + int_to_bytes_length(par_idx, 4, False)
				self.internal_buffer[par_idx][buffer_idx] = self._blake2_varable_hash(temp, 1024)
			else:
				# Derive Indexes from inital random values every round for Argon2i
				# For Argon2id use Argon2i for the first few itterations. Then switch to Argon2d.
				if self.hash_type == 1 or (self.hash_type == 2 and time_idx == 0 and segment_idx < 2):
					J1, temp_par_idx = pseudo_rands[2*idx], pseudo_rands[2*idx+1]
				else:
					# Derive current indexes from the first bytes of the previous buffer internal_buffer
					J1 = bytes_to_int(self.internal_buffer[par_idx][(buffer_idx-1)%self.column_count][0:4], False)
					temp_par_idx = bytes_to_int(self.internal_buffer[par_idx][(buffer_idx-1)%self.column_count][4:8], False)

				# Use the second index to choose a random paralization index from the internal buffer.
				# This is used in the second argument in the _chacha_compress algorithum
				temp_par_idx %= self.parallelism

				#Calculate the Reference Area Size to use in the calucation of the _chacha_compress second argument starting position
				if time_idx == 0:
					if segment_idx == 0 or temp_par_idx == par_idx:
						temp_par_idx = par_idx
						ref_area_size = buffer_idx - 1
					elif idx == 0:
						ref_area_size = segment_idx * self.segment_length - 1
					else:
						ref_area_size = segment_idx * self.segment_length
				elif temp_par_idx == par_idx or idx == 0: # same_lane 
					ref_area_size = self.column_count - self.segment_length + idx - 1
				else:
					ref_area_size = self.column_count - self.segment_length

				#Do calculation to slide the starting buffer of the _chacha_compress second argument
				rel_pos = ref_area_size - 1 - ((ref_area_size * ((J1 ** 2) >> 32)) >> 32)
				start_pos = 0

				#Possobly slide the slide the starting buffer of the _chacha_compress second argument
				#Combine the calculated positions and limit it by the number of columns. 
				if time_idx != 0 and segment_idx != 3:
					start_pos = (segment_idx + 1) * self.segment_length
				j_prime = (start_pos + rel_pos) % self.column_count

				# Mix the previous and reference block to create the next block.
				new_block = self._chacha_compress(self.internal_buffer[par_idx][(buffer_idx-1)%self.column_count], self.internal_buffer[temp_par_idx][j_prime])

				#This is a new case for the newest version of the argon algorithum
				if time_idx != 0 and self.argon_version == 0x13:
					new_block = fixedlen_xor(self.internal_buffer[par_idx][buffer_idx], new_block)

				#Copy the new output data in to the correct element of the internal buffer
				self.internal_buffer[par_idx][buffer_idx] = new_block

		# If we are run in a separate thread, then B is a copy.  Return changes.
		return self.internal_buffer[par_idx][segment_idx*self.segment_length:(segment_idx+1)*self.segment_length]


	def _chacha_compress(self, temp1, temp2):
		#XOR the input values to be used at the end to xor before returning the data
		xored_temp = fixedlen_xor(temp1, temp2)
		int_array = []
		ret = [None] * 128

		#Split xored data into 8 128byte rows to do a modified ChaCha Permutation on each row
		for x in range(8):
			int_array += self._chacha_permutation(xored_temp[x*128:(x+1)*128])

		#For each Column Mix the values, Do a ChaCha Permutation then unmix the columns
		for col_idx in range(8):
			column_int_array = []

			#Take 16 bytes from each of the columns and reorder them
			for row_idx in range(8):
				column_int_array.append(int_array[(2*col_idx)+(16*row_idx)])
				column_int_array.append(int_array[(2*col_idx)+(16*row_idx) + 1])

			#Do a modified ChaCha Permutation on each row with the newly mixed rows. (The Old Columns)
			column_output = self._chacha_permutation(intarray_to_bytes(column_int_array, 8))

			#Invert the reordering of the columns and rows after the chacha permutation
			for row_idx in range(8):
				ret[(col_idx*2) + (row_idx*16)]   = column_output[2*row_idx]
				ret[(col_idx*2) + (row_idx*16)+1] = column_output[(2*row_idx)+1]

		#Final XOR with the origional xored value with the chacha Permutation output
		ret = intarray_to_bytes(ret, 8)
		return fixedlen_xor(ret, xored_temp)
			
	def _chacha_permutation(self, temp_buffers):
		if type(temp_buffers) == bytes:
			temp_buffers = bytes_to_intarray(temp_buffers, 8)

		#Do Each Column
		temp_buffers[0], temp_buffers[4], temp_buffers[8],  temp_buffers[12] = self._modified_chacha_quarter_round(temp_buffers[0], temp_buffers[4], temp_buffers[8],  temp_buffers[12])
		temp_buffers[1], temp_buffers[5], temp_buffers[9],  temp_buffers[13] = self._modified_chacha_quarter_round(temp_buffers[1], temp_buffers[5], temp_buffers[9],  temp_buffers[13])
		temp_buffers[2], temp_buffers[6], temp_buffers[10], temp_buffers[14] = self._modified_chacha_quarter_round(temp_buffers[2], temp_buffers[6], temp_buffers[10], temp_buffers[14])
		temp_buffers[3], temp_buffers[7], temp_buffers[11], temp_buffers[15] = self._modified_chacha_quarter_round(temp_buffers[3], temp_buffers[7], temp_buffers[11], temp_buffers[15])
			
		#Do Each Diagonal
		temp_buffers[0], temp_buffers[5], temp_buffers[10], temp_buffers[15] = self._modified_chacha_quarter_round(temp_buffers[0], temp_buffers[5], temp_buffers[10], temp_buffers[15])
		temp_buffers[1], temp_buffers[6], temp_buffers[11], temp_buffers[12] = self._modified_chacha_quarter_round(temp_buffers[1], temp_buffers[6], temp_buffers[11], temp_buffers[12])
		temp_buffers[2], temp_buffers[7], temp_buffers[8],  temp_buffers[13] = self._modified_chacha_quarter_round(temp_buffers[2], temp_buffers[7], temp_buffers[8],  temp_buffers[13])
		temp_buffers[3], temp_buffers[4], temp_buffers[9],  temp_buffers[14] = self._modified_chacha_quarter_round(temp_buffers[3], temp_buffers[4], temp_buffers[9],  temp_buffers[14])

		return temp_buffers

	def _modified_chacha_quarter_round(self, a, b, c, d):
		# Modified to + 2 * a * b
		# Limit the multiplication input to the first 32-bytes for input data
		a = asint((a + b) + 2 * asint(a, 32) * asint(b, 32), self.blocksize)
		d ^= a
		d = shift_rotate_right(d, self.rotations[0], self.blocksize)

		#Modified to + 2 * c * d
		# Limit the multiplication input to the first 32-bytes for input data
		c = asint((c + d) + 2 * asint(c, 32) * asint(d, 32), self.blocksize)
		b ^= c
		b = shift_rotate_right(b, self.rotations[1], self.blocksize)

		#Modified to + 2 * a * b
		# Limit the multiplication input to the first 32-bytes for input data
		a = asint((a + b) + 2 * asint(a, 32) * asint(b, 32), self.blocksize)
		d ^= a
		d = shift_rotate_right(d, self.rotations[2], self.blocksize)

		#Modified to + 2 * c * d
		# Limit the multiplication input to the first 32-bytes for input data
		c = asint(d + c + 2 * asint(c, 32) * asint(d, 32), self.blocksize)
		b ^= c
		b = shift_rotate_right(b, self.rotations[3], self.blocksize)

		return [a,b,c,d]



if __name__ == '__main__':
	time_cost = 150
	memory_cost = 24*8
	parallelism = 24

	test = Argon2(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)
	output = test.hash2id(b'passwordpasswordpasswordpassword', b'randomsaltrandomsaltrandomsaltrandomsalt')
	print(f"T:{time_cost} M:{memory_cost} P:{parallelism} {output.hex()}")