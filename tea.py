import math
from cryptopals_lib import *

class TEA():
	MAX_UINT = 0xffffffff
	DELTA = 0x9E3779B9 #2654435769
	INIT_TEMP = 0xC6EF3720

	def __init__(self, key):
		self.key = bytes_to_intarray(key, 4)
		if len(self.key) != 4:
			raise ValueException("Key is not 16 bytes long")

		

	def encrypt(self, plaintext):
		output = []
		#Split input
		int_plaintext = bytes_to_intarray(plaintext, 4)
		
		#Pad so its a mult of 2
		if len(int_plaintext) %2 == 1:
			int_plaintext.append(0)

		#Split into chunks of length 2
		for idx in range(0, len(int_plaintext), 2):
			output += self._block_encrypt(int_plaintext[idx], int_plaintext[idx + 1])

		#print(output)

		return intarray_to_bytes(output, 4)

	def encrypt_xtea(self, plaintext):
		output = []
		#Split input
		int_plaintext = bytes_to_intarray(plaintext, 4)
		
		#Pad so its a mult of 2
		if len(int_plaintext) %2 == 1:
			int_plaintext.append(0)

		#Split into chunks of length 2
		for idx in range(0, len(int_plaintext), 2):
			output += self._block_encrypt_xtea(int_plaintext[idx], int_plaintext[idx + 1])

		#print(output)

		return intarray_to_bytes(output, 4)
		

	def _block_encrypt(self, y, z):
		temp = 0#INIT_TEMP

		#32 Rounds
		for _ in range(32):
			temp = asint32(temp + self.DELTA)
			y = asint32(y + (
					asint32(asint32(z << 4) + self.key[0]) ^
					asint32(z + temp) ^
					asint32((z >> 5) + self.key[1])
			))
			z = asint32(z + (
					asint32(asint32(y << 4) + self.key[2]) ^
					asint32(y + temp) ^
					asint32((y >> 5) + self.key[3])
			))

		return [y,z]

	def _block_encrypt_xtea(self, y, z):
		temp = 0#INIT_TEMP

		#32 Rounds
		for _ in range(32):
			y = asint32(y + (
					asint32((asint32(z << 4) ^ (z >> 5)) + z) ^
					asint32(temp + self.key[temp&3])
			))
			temp = asint32(temp + self.DELTA)
			z = asint32(z + (
					asint32((asint32(y << 4) ^ (y >> 5)) + y) ^
					asint32(temp + self.key[(temp >> 11)&3])
			))

		return [y,z]

	def decrypt(self, ciphertext):
		output = []
		#Split input
		int_ciphertext = bytes_to_intarray(ciphertext, 4)

		#Split into chunks of length 2
		for idx in range(0, len(int_ciphertext), 2):
			output += self._block_decrypt(int_ciphertext[idx], int_ciphertext[idx + 1])

		return intarray_to_bytes(output, 4)

	def decrypt_xtea(self, ciphertext):
		output = []
		#Split input
		int_ciphertext = bytes_to_intarray(ciphertext, 4)

		#Split into chunks of length 2
		for idx in range(0, len(int_ciphertext), 2):
			output += self._block_decrypt_xtea(int_ciphertext[idx], int_ciphertext[idx + 1])

		return intarray_to_bytes(output, 4)


	def _block_decrypt(self, y, z):
		temp = self.INIT_TEMP

		#32 Rounds
		for _ in range(32):
			z = asint32(z - (
					asint32(asint32(y << 4) + self.key[2]) ^
					asint32(y + temp) ^
					asint32((y >> 5) + self.key[3])
			))
			y = asint32(y - (
					asint32(asint32(z << 4) + self.key[0]) ^
					asint32(z + temp) ^
					asint32((z >> 5) + self.key[1])
			))

			temp = asint32(temp - self.DELTA)
			#print(z,y,temp)
		return [y,z]

	def _block_decrypt_xtea(self, y, z):
		temp = self.INIT_TEMP

		#32 Rounds
		for _ in range(32):
			z = asint32(z - (
					asint32((asint32(y << 4) ^ (y >> 5)) + y) ^
					asint32(temp + self.key[(temp>>11) & 3])
			))
			temp = asint32(temp - self.DELTA)
			y = asint32(y - (
					asint32((asint32(z << 4) ^ (z >> 5)) + z) ^
					asint32(temp + self.key[temp & 3])
			))

			#print(z,y,temp)



		return [y,z]



if __name__ == '__main__':

	#Test Vectors https://github.com/liut/TeaCrypt/blob/master/tea/tea_test.go

	key = hex_to_bytes("00000000000000000000000000000000")
	tea = TEA(key)
	message = b"\x00" * 8
	ciphertext = tea.encrypt(message)
	print(f"Ciphertext: {ciphertext.hex()}")
	#Ciphertext: 0a3aea4140a9ba94
	message2 = tea.decrypt(ciphertext)
	print(f"Message: {message2.hex()}")
	#Message: 0000000000000000


	key = hex_to_bytes("00000000000000000000000000000000")
	tea = TEA(key)
	message = b"\x04\x03\x02\x01\x08\x07\x06\x05"
	ciphertext = tea.encrypt(message)
	print(f"Ciphertext: {ciphertext.hex()}")
	#Ciphertext: f39c2f6a553ccffc
	message2 = tea.decrypt(ciphertext)
	print(f"Message: {message2.hex()}")
	#Message: 0403020108070605

	key = hex_to_bytes("33221100 77665544 BBAA9988 FFEEDDCC")
	tea = TEA(key)
	message = b"\x04\x03\x02\x01\x08\x07\x06\x05"
	ciphertext = tea.encrypt(message)
	print(f"Ciphertext: {ciphertext.hex()}")
	#Ciphertext: a2c0b1deb35d747e
	message2 = tea.decrypt(ciphertext)
	print(f"Message: {message2.hex()}")
	#Message: 0403020108070605

	key = hex_to_bytes("33221100 77665544 BBAA9988 FFEEDDCC")
	tea = TEA(key)
	message = b"\x67\x45\x23\x01\xEF\xCD\xAB\x89"
	ciphertext = tea.encrypt(message)
	print(f"Ciphertext: {ciphertext.hex()}")
	#Ciphertext: 926b6c123e3a65c0
	message2 = tea.decrypt(ciphertext)
	print(f"Message: {message2.hex()}")
	#Message: 67452301efcdab89

	#Test Vectors https://www.tayloredge.com/reference/Mathematics/XTEA.pdf

	key = intarray_to_bytes([0x27F917B1,0xC1DA8993,0x60E2ACAA,0xA6EB923D], 4)
	tea = TEA(key)
	message = intarray_to_bytes([0xAF20A390,0x547571AA], 4)
	ciphertext = tea.encrypt_xtea(message)
	print(f"Ciphertext: {ciphertext.hex()}")
	#Ciphertext: af2864d28322200a
	message2 = tea.decrypt_xtea(ciphertext)
	print(f"Message: {message2.hex()}")
	#Message: 90a320afaa717554


	key = intarray_to_bytes([0x31415926,0x53589793,0x23846264,0x33832795], 4)
	tea = TEA(key)
	message = intarray_to_bytes([0x02884197,0x16939937], 4)
	ciphertext = tea.encrypt_xtea(message)
	print(f"Ciphertext: {ciphertext.hex()}")
	#Ciphertext: 7d00e246eac2bb58
	message2 = tea.decrypt_xtea(ciphertext)
	print(f"Message: {message2.hex()}")
	#Message: 9741880237999316
