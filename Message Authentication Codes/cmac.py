from aes_lib import AES
from cryptopals_lib import int_to_bytes, bytes_to_int, fixedlen_xor, asint, to_blocks


class CMAC():
	"""docstring for CMAC"""
	def __init__(self, key):
		self.key = key
		self.block_size = 16
		self.crypt = AES(self.key)
		self.subkeys = self._gen_subkeys()
		

	def _gen_subkeys(self):
		#Encrypt a Zero block 
		enc_zeros = self.crypt.aes_block_encryption(b"\x00" * self.block_size)

		#Left Shift encrypted zero budder output by 1
		key_1 = int_to_bytes(asint(bytes_to_int(enc_zeros) << 1, self.block_size*8))

		#If first bit is set xor byte
		if enc_zeros[0] & 0x80 != 0:
			key_1[-1] ^= 0x87

		#Left Shift key_1 output by 1
		key_2 = int_to_bytes(asint(bytes_to_int(key_1) << 1, self.block_size*8))
		#print(key_2)

		#If first bit is set xor byte
		if key_1[0] & 0x80 != 0:
			tmp = fixedlen_xor(key_2[-1], 0x87)
			key_2 = key_2[:-1] + int_to_bytes(tmp)

		return key_1, key_2

	def _pad_message(self, message):
		#Pad the message
		padding_num = len(message) % self.block_size
		if len(message) == 0 or padding_num != 0:
			message += b"\x80" + b"\x00" * (self.block_size - 1 - padding_num)
			xor_key = self.subkeys[1]
		else:
			xor_key = self.subkeys[0]

		#Convert into blocks of 128 bits
		message_blocks = to_blocks(message, 16)
		#print([x.hex() for x in message_blocks])

		#Xor last block with the approprate key
		message_blocks[-1] = fixedlen_xor(message_blocks[-1], xor_key)
		return message_blocks


	def hash(self, message):
		#Pad Message
		message_blocks = self._pad_message(message)
		

		hash_output = b"\x00" * self.block_size

		for block in message_blocks:
			print(f"Round: {block.hex()}")
			tmp = fixedlen_xor(block, hash_output)
			hash_output = self.crypt.aes_block_encryption(tmp)

		return hash_output

	def hashdigest(self, message):
		return self.hash(message).hex()

if __name__ == '__main__':
	
	#Test Vectors
	k  = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
	
	m1 = b"" 

	m2 = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"

	m3 = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" \
		 b"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" \
		 b"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11"

	m4 = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" \
		 b"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" \
		 b"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" \
		 b"\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"

	c = CMAC(k)

	k1,k2 = c._gen_subkeys()

	print(f"k1 : {k1.hex()}")
	#k1 : fbeed618357133667c85e08f7236a8de
	print(f"k2 : {k2.hex()}")
	#k2 : f7ddac306ae266ccf90bc11ee46d513b

	print(f"t1 : {c.hash(m1).hex()}")
	#t1 : bb1d6929e95937287fa37d129b756746
	print(f"t2 : {c.hash(m2).hex()}")
	#t2 : 070a16b46b4d4144f79bdd9dd04a287c
	print(f"t3 : {c.hash(m3).hex()}")
	#t3 : dfa66747de9ae63030ca32611497c827
	print(f"t4 : {c.hash(m4).hex()}")
	#t4 : 51f0bebf7e3b9d92fc49741779363cfe