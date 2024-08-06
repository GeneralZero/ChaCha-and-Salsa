import sys
sys.path.append("..")

from cryptopals_lib import fixedlen_xor, to_blocks, int_to_bytes

class DES():
	"""docstring for DES"""
	def __init__(self,key,IV=None):
		
		self.sbox = [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
					  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
					 [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
					  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
					 [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
					  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
					 [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
					  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
					 [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
					  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
					 [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
					  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
					 [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
					  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
					 [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
					  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],]

		self.pre_subkey_permutation = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,
					                   62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,60,52,44,36,28,20,12,4,27,19,11,3]

		self.subkey_permutation = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,25,7,15,6,26,19,12,1,40,51,30,36,46,54,
					               29,39,50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31]

		self.inital_perm = [57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,
							63,55,47,39,31,23,15,7,56,48,40,32,24,16,8,0,58,50,42,34,26,18,10,2,
							60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6]

		self.expantion_table = [31,0,1,2,3,4,3,4,5,6,7,8,7,8,9,10,11,12,11,12,13,14,15,16,15,16,17,18,19,20,
		                        19,20,21,22,23,24,23,24,25,26,27,28,27,28,29,30,31,0]

		self.sbox_perm = [15,6,19,20,28,11,27,16,0,14,22,25,4,17,30,9,1,7,23,13,31,26,2,8,18,12,29,5,21,10,3,24]

		self.final_permutation = [39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
								  36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,
								  33,1,41,9,49,17,57,25,32,0,40,8,48,16,56,24]

		self.block_size = 64	

		self.left_rotations = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

		#Create Subkeys
		self.key = key
		self._gen_subkeys(self.key)

	def _gen_subkeys(self, key):
		self.subkeys = ["" for _ in range(16)]
		binary_key = "".join(["{0:>08b}".format(int(x)) for x in key])
		output_key = ""


		#Permutate the key using PC1
		for index in self.pre_subkey_permutation:
			output_key += binary_key[index]

		#Split into Left and Right
		left_key, right_key = output_key[:28], output_key[28:]

		for round_num in range(16):
			#shift_rotate_left the left key
			left_key = left_key[self.left_rotations[round_num]:] + left_key[:self.left_rotations[round_num]]

			#shift_rotate_left the right key
			right_key = right_key[self.left_rotations[round_num]:] + right_key[:self.left_rotations[round_num]]

			#Join the keys together into a full key
			full_key = left_key + right_key

			#Create the subkeys
			for index in self.subkey_permutation:
				self.subkeys[round_num] += full_key[index]

	def _round_opperation(self, round_key, right_message):
		right_message_expanded = ""
		s_box_sub = ""
		s_box_out = ""

		#Expand the message to 42 bytes using a permutation with duplicate entries 
		for index in self.expantion_table:
			right_message_expanded += right_message[index]

		#Xor round key with expanded right message
		right_message_expanded = fixedlen_xor(round_key, right_message_expanded)
		
		#Convert right key into 6bit sbox inputs
		sbox_inputs = to_blocks(right_message_expanded, 6)

		#Do sbox subsitution
		for sbox_index, sbox_input in enumerate(sbox_inputs):
			#Generate row and coulmn from input data
			#Row is the first and last bit of the 6bit input
			row_num = int(sbox_input[0] + sbox_input[-1], 2)
			#Comumn is the second through fifth bit of the 6bit input
			column_num = int(sbox_input[1:5], 2)

			#Do sbox subistution with the correct sub index and round and column index
			s_box_sub += "{0:>04b}".format(self.sbox[sbox_index][row_num*16 + column_num])

		#Do final permutation on sbox output
		for index in self.sbox_perm:
			s_box_out += s_box_sub[index]

		return s_box_out


	def _encrypt_message_chunk(self, message_chunk):
		output_chunk = ""

		#Do Permentation on the block of the plaintext message
		for index in self.inital_perm:
			output_chunk += message_chunk[index]

		#Break the message into left and right
		left_message, right_message = output_chunk[:32], output_chunk[32:]

		#Do rounds
		for round_key in self.subkeys:
			#Backup the previous right message
			right_message_copy = right_message

			#Do the Round opperation with the round key
			tmp = self._round_opperation(round_key, right_message)

			#Set Right message to the xor of the round opperation and the left message
			right_message = fixedlen_xor(left_message, tmp)

			#Set the left message to the old right message
			left_message = right_message_copy

		#Join the message parts together but swap the left and the right side
		full_message = right_message + left_message
		output_chunk = ""

		#Do final Permutaiton before the data is outputed
		for index in self.final_permutation:
			output_chunk += full_message[index]

		return int_to_bytes(int(output_chunk, 2))

	def encrypt(self, message):
		binary_message = "".join(["{0:>08b}".format(int(x)) for x in message])
		output_message = b""
		
		#Opperate on each of the 64 byte chunks
		for chunk in to_blocks(binary_message, self.block_size):
			output_message += self._encrypt_message_chunk(chunk)

		return output_message

	def encrypt_3(self, message):
		#Break input key into keys for 3DES
		if len(self.key) == 16:
			key1 = self.key[:8]
			key2 = self.key[8:16]
			key3 = key1
		elif len(self.key) == 24:
			key1 = self.key[:8]
			key2 = self.key[8:16]
			key3 = self.key[16:24]
		else:
			raise Exception("Invaid Key fror 3DES")

		#Do Encryption with first key
		self._gen_subkeys(key1)
		message = self.encrypt(message)
		print(message)

		#Do Decryption with second key
		self._gen_subkeys(key2)
		message = self.decrypt(message)
		print(message)

		#Do Encryption with third key
		self._gen_subkeys(key3)
		return self.encrypt(message)

	def decrypt(self, message):
		binary_message = "".join(["{0:>08b}".format(int(x)) for x in message])
		output_message = b""

		#Decryption is the same as encryption but with the subkeys in reverse order. 
		#Reverse the order of the subkeys
		self.subkeys.reverse()
		
		#Opperate on each of the 64 byte chunks
		for chunk in to_blocks(binary_message, self.block_size):
			output_message += self._encrypt_message_chunk(chunk)

		return output_message
		
	def decrypt_3(self, message):
		#Break input key into keys for 3DES
		if len(self.key) == 16:
			key1 = self.key[:8]
			key2 = self.key[8:16]
			key3 = key1
		elif len(self.key) == 24:
			key1 = self.key[:8]
			key2 = self.key[8:16]
			key3 = self.key[16:24]
		else:
			raise Exception("Invaid Key fror 3DES")

		#Do Decryption with third key
		self._gen_subkeys(key3)
		message = self.decrypt(message)
		print(message)

		#Do Encryption with second key
		self._gen_subkeys(key2)
		message = self.encrypt(message)
		print(message)

		#Do Decryption with first key
		self._gen_subkeys(key1)
		message = self.decrypt(message)
		return message

if __name__ == '__main__':
	des1 = DES(b"64bitKey")
	ct = des1.encrypt(b"Secret Message!!")
	#print(ct)
	pt = des1.decrypt(ct)
	#print(pt)

	des2 = DES(b"64bitKey32bitKey16bitKey")
	ct = des2.encrypt_3(b"Secret Message!!")
	print(ct)
	pt = des2.decrypt_3(ct)
	print(pt)

