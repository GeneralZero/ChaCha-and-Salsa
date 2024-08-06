from cryptopals_lib import intarray_to_bytes, bytes_to_intarray, shift_rotate_left, hex_to_bytes, asint32, int_to_bytes

def print_state(state):
	print("{:08x} {:08x} {:08x} {:08x}  ".format(state[0], state[1], state[2],  state[3]), end="")
	print("{:08x} {:08x} {:08x} {:08x}  ".format(state[4], state[5], state[6],  state[7]), end="")
	print("{:08x} {:08x} {:08x} {:08x}".format(state[8], state[9], state[10], state[11]))

def gimli(intarray, rounds=24):
	#Do rounds backwards since the round number is par of the contstant
	for round_num in range(rounds, 0, -1):

		#For Each Column Do the Block info
		for column in range(4):
			#Get shifted Temp varables
			x = shift_rotate_left(intarray[    column], 24)
			y = shift_rotate_left(intarray[4 + column], 9)
			z =                   intarray[8 + column]

			#Do Opperation and store the data
			intarray[8 + column] = x ^ asint32(z << 1) ^ asint32((y & z) << 2)
			intarray[4 + column] = y ^ x               ^ asint32((x | z) << 1)
			intarray[    column] = z ^ y               ^ asint32((x & y) << 3)


		if round_num & 3 == 0:
			#Swap values 0<->1 and 2<->3
			intarray[0], intarray[1] = intarray[1], intarray[0]
			intarray[2], intarray[3] = intarray[3], intarray[2]

			#Add contstant mo dified by round number
			intarray[0] ^= (0x9e377900 | round_num)

		elif round_num & 3 == 2:
			#Swap values 0<->2 and 1<->3
			intarray[0], intarray[2] = intarray[2], intarray[0]
			intarray[1], intarray[3] = intarray[3], intarray[1]

	return intarray

class Gimli_hash():
	def __init__(self):
		self.state_length = 12
		self.byte_rate = 16
		self.state = [0 for x in range(self.state_length)]

	def _finalize(self, message_length):
		#Calculate the index for the padding
		padding_loc = (message_length % self.byte_rate)
		int_index = padding_loc // (self.byte_rate // 4)
		byte_index = padding_loc % (self.byte_rate // 4)
		padding_int = 0x1F << (8*byte_index)

		#XOR the correct data
		self.state[int_index] ^= padding_int

		#Add Second bit of padding to the begining of the 4th 32-bit intager
		self.state[3] ^= 0x80000000

	def hash(self, message, outputsize=32):
		block_num = 0

		for idx, byte in enumerate(message):
			#Calculate the index of the 32-bit int array
			block_num = idx // (self.byte_rate // 4)

			#When a full block is done call gimli algorithum
			if idx % self.byte_rate == 0 and block_num != 0:
				self.state = gimli(self.state)

			#Update Blocks in correct endian to the first 4 state blocks only
			self.state[block_num % 4] ^= (byte << 8 * (idx % 4))

		#Finalize Message with constatnts and padding info
		self._finalize(len(message))

		#Squeeze Blocks
		output = b''
		idx = 0
		block_length = min(outputsize, self.byte_rate)

		#Output Data
		while outputsize > 0:
			#Call Gimli
			#gimli is also called before any output data is copyed
			#This call was usualy in the finalize block but made more sense here
			if (idx * 4) % self.byte_rate == 0:
				self.state = gimli(self.state)
				idx = 0

			#Copy 32bit intager to output
			output += int_to_bytes(self.state[idx], False)

			#Update loop varables
			idx +=1
			outputsize -= 4

		return output
		
	def hash_digest(self, message):
		return self.hash(message).hex()


if __name__ == '__main__':
	#Gimli Test Vector
	input0 = hex_to_bytes("000000009e3779ba3c6ef37adaa66d4678dde7241715611ab54cdb2e53845566f1bbcfc88ff34a5a2e2ac522cc624026")
	int_input = bytes_to_intarray(input0, 4, byte_order="big")

	output0 = gimli(int_input)
	print(intarray_to_bytes(output0, 4, byte_order="big").hex())
	#ba11c85a91bad119380ce880d24c2c683eceffea277a921c4f73a0bdda5a9cd884b673f034e52ff79e2bef49f41bb8d6
	#ba11c85a91bad119380ce880d24c2c683eceffea277a921c4f73a0bdda5a9cd884b673f034e52ff79e2bef49f41bb8d6

	#Gimli Hash Test Vectors
	input1 = hex_to_bytes("5468657265277320706c656e747920666f722074686520626f7468206f662075732c206d61792074686520626573742044776172662077696e2e")
	input2 = hex_to_bytes("496620616e796f6e652077617320746f2061736b20666f72206d79206f70696e696f6e2c2077686963682049206e6f74652074686579277265206e6f742c204927642073617920776520776572652074616b696e6720746865206c6f6e67207761792061726f756e642e")
	input3 = hex_to_bytes("537065616b20776f7264732077652063616e20616c6c20756e6465727374616e6421")
	input4 = hex_to_bytes("49742773207472756520796f7520646f6e277420736565206d616e792044776172662d776f6d656e2e20416e6420696e20666163742c20746865792061726520736f20616c696b6520696e20766f69636520616e6420617070656172616e63652c2074686174207468657920617265206f6674656e206d697374616b656e20666f722044776172662d6d656e2e20416e64207468697320696e207475726e2068617320676976656e207269736520746f207468652062656c696566207468617420746865726520617265206e6f2044776172662d776f6d656e2c20616e6420746861742044776172766573206a75737420737072696e67206f7574206f6620686f6c657320696e207468652067726f756e64212057686963682069732c206f6620636f757273652c207269646963756c6f75732e")
	input5 = b''
	hash = Gimli_hash()
	print(hash.hash_digest(input1))
	#4afb3ff784c7ad6943d49cf5da79facfa7c4434e1ce44f5dd4b28f91a84d22c8
	#4afb3ff784c7ad6943d49cf5da79facfa7c4434e1ce44f5dd4b28f91a84d22c8

	hash = Gimli_hash()
	print(hash.hash_digest(input2))
	#ba82a16a7b224c15bed8e8bdc88903a4006bc7beda78297d96029203ef08e07c
	#ba82a16a7b224c15bed8e8bdc88903a4006bc7beda78297d96029203ef08e07c

	hash = Gimli_hash()
	print(hash.hash_digest(input3))
	#8dd4d132059b72f8e8493f9afb86c6d86263e7439fc64cbb361fcbccf8b01267
	#8dd4d132059b72f8e8493f9afb86c6d86263e7439fc64cbb361fcbccf8b01267
	
	hash = Gimli_hash()
	print(hash.hash_digest(input4))
	#8887a5367d961d6734ee1a0d4aee09caca7fd6b606096ff69d8ce7b9a496cd2f
	#8887a5367d961d6734ee1a0d4aee09caca7fd6b606096ff69d8ce7b9a496cd2f
	
	hash = Gimli_hash()
	print(hash.hash_digest(input5))
	#b0634b2c0b082aedc5c0a2fe4ee3adcfc989ec05de6f00addb04b3aaac271f67
	#b0634b2c0b082aedc5c0a2fe4ee3adcfc989ec05de6f00addb04b3aaac271f67

