from cryptopals_lib import *  
from pbkdf2 import pbkdf2
from chacha import salsa_key_schedule
import os, hashlib



class Scrypt():
	"""docstring for Scrypt"""
	def __init__(self, itterations=16384, memory_cost=8, parallel_cost=1, keylength=64):
		#Check that memory factor * parallel factor is not greater than 2^30
		if memory_cost * parallel_cost > 2 ** 30:
			raise Exception("Too much memory in use.")
		self.memory_cost =  memory_cost
		self.parallel_cost =  parallel_cost

		#Check if Itterations is not a power of 2 greater than 2^0
		if itterations < 2 or (itterations & (itterations -1)):
			raise Exception("itterations not a power of 2.")
		self.itterations = itterations

		self.keylength = keylength

		#Initalize other temp buffers
		self.memory_buffer = [ 0 ] * (self.memory_cost << 6)
		self.itter_buffer  = [ 0 ] * ((self.memory_cost * self.itterations) << 5)


	def _smix(self, buffer, round_num):
		index_from = (round_num * self.memory_cost) << 5
		block_size = (self.memory_cost<< 5)

		#Populate the Memory buffer from the input buffer
		self.memory_buffer[:block_size] = buffer[index_from: index_from + block_size]

		#Mix the memory buffer and update the itteration buffer
		for i in range(self.itterations):
			index_to = i * block_size
			self.itter_buffer[index_to:index_to + block_size] = self.memory_buffer[:block_size]

			#Do a Block mix on the memory_buffer
			self.memory_buffer = self._block_mix(self.memory_buffer)

		#Part 2 of Mixing ???
		for i in range(self.itterations):
			#Calculate the staring index from a static offset in the memory_buffer
			#This memory buffer is always changing so does the start_index
			start_index = self.memory_buffer[(2 * self.memory_cost -1) << 4] & (self.itterations -1)

			#Select a part of the itteration buffer and XOR a block into the memory buffer
			for j in range(block_size):
				self.memory_buffer[j] ^= self.itter_buffer[(start_index * block_size) + j]

			#Do a Block mix on the memory_buffer
			self.memory_buffer = self._block_mix(self.memory_buffer)

		#Copy the first block of the memory buffer to the output buffer at the round offset
		buffer[index_from:index_from + block_size] = self.memory_buffer[:block_size]

		return buffer

	def _block_mix(self, buffer):
		start_index = (2 * self.memory_cost - 1) << 4

		#Create a smaller temp buffer for the salsa rounds
		temp = buffer[start_index:start_index+16]

		#Actual Block Mix with salsa key schedule algorithum with 8 rounds
		for i in range(2*self.memory_cost):
			#XOR the buffer block baised on the index number
			for j in range(16):
				temp[j] ^= buffer[(i <<4) + j]

			#Salsa round with the temp buffer
			temp = salsa_key_schedule(temp, rounds=8)

			#Copy the temp buffer to the output buffer
			index_to = (self.memory_cost << 5) + (i << 4)
			buffer[index_to:index_to+16] = temp[:16]


		#Copy Blocks around
		for i in range(self.memory_cost): 
			index_from = (self.memory_cost + i) << 5
			index_to = i << 4
			#Copy a block from a later point in the buffer to a the ith block
			buffer[index_to:index_to + 16] = buffer[index_from:index_from + 16]

		#Copy Blocks around again
		for i in range(self.memory_cost):
			index_from = ((self.memory_cost + i) << 5) + 16
			index_to = (self.memory_cost + i) << 4
			#Copy a block from a later point in the buffer to a earlyer buffer
			buffer[index_to:index_to + 16] = buffer[index_from:index_from + 16]

		return buffer

	def hash(self, password, salt=None):
		self.password = password

		if salt == None:
			self.salt = os.urandom(16)
		else:
			self.salt = salt

		#Initalize the buffer using a single sha256-pbkdf2
		buffer = pbkdf2(self.password, self.salt, itterations=1, keylength=((self.parallel_cost*self.memory_cost)<< 7), hashobj=hashlib.sha256)
		int_buffer = bytes_to_intarray(buffer, 4,  byte_order="little")

		#smix rounds
		for round_idx in range(self.parallel_cost):
			int_buffer = self._smix(int_buffer, round_num=round_idx)

		#Convert Ints back to byte string
		buffer = intarray_to_bytes(int_buffer, 4, byte_order="little")

		return pbkdf2(self.password, buffer, itterations=1, keylength=self.keylength, hashobj=hashlib.sha256)

if __name__ == '__main__':
	test = Scrypt(itterations=1024, memory_cost=1, parallel_cost=1, keylength=64)
	out = test.hash(password = b"correct horse battery staple", salt = b"seasalt")
	print(out.hex())
	#8dc98cddcf52dd725d52b913f7bf8386fa44e1406795aa661487f434007dff1680be6baddd724659316f7ff4663174a7a4ead1c95d5175cf284ac9ae8703e1fb
	
	test = Scrypt(itterations=1024, memory_cost=2, parallel_cost=1, keylength=64)
	out = test.hash(password = b"correct horse battery staple", salt = b"seasalt")
	print(out.hex())
	#77053f0f354002c0f2a240ce9c7b17625fb1440f87a714451217e901f7d03d748411b0bc8e4c150a573f40b98dfa816cf12bb6b01a7567970f1448d7d2a1367a

	test = Scrypt(itterations=1024, memory_cost=1, parallel_cost=2, keylength=64)
	out = test.hash(password = b"correct horse battery staple", salt = b"seasalt")
	print(out.hex())
	#cc93bb017c38aaf54901146bdc5d21c21be2314ea63ec0a4466ea44af50c8a5c87b5cd567b8205f69f601fc8ed66e4108c5b8f12474e06520de57b8fdcc484bc

	test = Scrypt(itterations=16384, memory_cost=8, parallel_cost=2, keylength=64)
	out = test.hash(password = b"correct horse battery staple", salt = b"seasalt")
	print(out.hex())
	#e3e97ec22c635ca626a6e977ae90c69845ee4c716b57e9c00757e508822fedd83d1d0539d2de1c241b830d4ce59d0bcba72d482217f193af07a125eb1c67455f
