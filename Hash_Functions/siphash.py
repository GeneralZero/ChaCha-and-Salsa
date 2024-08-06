import os, sys
sys.path.append("..")

from cryptopals_lib import fixedlen_xor, bytes_to_intarray, asint64, asint, asint32, bytes_to_int, int_to_bytes

class siphash():
	"""docstring for siphash"""
	def __init__(self, key):
		self.digest_size = 16
		self.block_size = 64

		self.input_length = 0
		self.first_input_64 = None
		
		#Check Key size
		assert len(key) == 16
		int_key0 = bytes_to_int(key[0:8], False)
		int_key1 = bytes_to_int(key[8:16], False)
		#print(int_key0, int_key1)

		#Set inital vectors with inital bytes with the key duplicated
		self.vectors = [
			(bytes_to_int(b"somepseu") ^ int_key0),
			(bytes_to_int(b"dorandom") ^ int_key1),
			(bytes_to_int(b"lygenera") ^ int_key0),
			(bytes_to_int(b"tedbytes") ^ int_key1),
		]
		#self._printVectors()

	def _sip_round(self, block):
		#Using a,b,c,d as 0,1,2,3 in the array
		temp_vectors = self.vectors

		#d ^ block
		temp_vectors[3] ^= block

		## 1 Round

		# (((b & 0x7ffffffffffff) << 13) | (b >> 51)) ^ (a + b)
		step_1 = asint64(temp_vectors[0] + temp_vectors[1])
		step_2 = ((asint(temp_vectors[1], 51) << 13) | (temp_vectors[1] >> 51)) ^ step_1
		step_3 = temp_vectors[2] + temp_vectors[3]
		step_4 = asint64(((temp_vectors[3] << 16) | (temp_vectors[3] >> 48)) ^ step_3)
		step_5 = asint64(step_2 + step_3)

		# print(f"e = {step_1}")
		# print(f"i = {step_2}")
		# print(f"f = {step_3}")
		# print(f"j = {step_4}")
		# print(f"h = {step_5}")
			
		#Set New Temp Vectors
		temp_vectors[0] = ((step_1 << 32) | (step_1 >> 32)) + step_4
		temp_vectors[1] = ((asint(step_2, 47) << 17) | (step_2 >> 47)) ^ step_5
		temp_vectors[3] = asint64(((step_4 << 21) | (step_4 >> 43)) ^ temp_vectors[0])

		#print(f"k = {temp_vectors[0]}")
		#print(f"l = {temp_vectors[1]}")
		#print(f"o = {temp_vectors[3]}")

		## 2nd Round
		step_1 = asint64(temp_vectors[0] + temp_vectors[1])
		step_2 = ((asint(temp_vectors[1], 51) << 13) | (temp_vectors[1] >> 51)) ^ step_1
		step_3 = ((step_5 << 32) | (step_5 >> 32)) + temp_vectors[3]
		step_4 = asint64(((temp_vectors[3] << 16) | (temp_vectors[3] >> 48)) ^ step_3)
		step_5 = asint64(step_2 + step_3)
		step_6 = asint64(((step_1 << 32) | (step_1 >> 32)) + step_4)

		#print(f"p = {step_1}")
		#print(f"q = {step_2}")
		#print(f"r = {step_3}")
		#print(f"s = {step_4}")
		#print(f"t = {step_5}")
		#print(f"u = {step_6}")

		#Set New Temp Vectors
		temp_vectors[0] = step_6 ^ block
		temp_vectors[1] = ((asint(step_2, 47) << 17) | (step_2 >> 47)) ^ step_5
		temp_vectors[2] = ((asint32(step_5) << 32)  | (step_5 >> 32))
		temp_vectors[3] = ((asint(step_4, 43) << 21) | (step_4 >> 43)) ^ step_6

		self.vectors = temp_vectors
		#return temp_vectors


		
	def _printVectors(self):
		print(f"V1: {hex(self.vectors[0])}")
		print(f"V2: {hex(self.vectors[1])}")
		print(f"V3: {hex(self.vectors[2])}")
		print(f"V4: {hex(self.vectors[3])}")

	def hash(self, data):
		#Split into 8 length chunks
		self.input_length = len(data)

		#Process the full block
		max_idx = (len(data)//8)*8
		#print(f"v: {self.vectors}")

		for idx in range(0, max_idx, 8):
			#Do SIP Round on block
			int_data = bytes_to_int(data[idx:idx+8], False)
			self._sip_round(int_data)
			#print(f"v: {self.vectors}")

		#Set Finalize Varables 
		self.input_64 = bytes_to_int(data[max_idx:], False)

		#Finalize a partial blocks
		return self._finalize()
			


	def _finalize(self):
		#Setup end data 
		end_data = ((self.input_length & 0xff) << 56)
		end_data |= self.input_64
		#print(f"v1: {self.vectors}")


		#Do SIP round with data end
		self._sip_round(end_data)
		#print(f"v2: {self.vectors}")


		#Finalize
		self.vectors[2] ^= 0xff
		#print(f"v3: {self.vectors}")

		#Do Double sipround with 0 data
		self._sip_round(0)
		self._sip_round(0)
		#print(f"v4: {self.vectors}")

		return int_to_bytes(self.vectors[0] ^ self.vectors[1] ^ self.vectors[2] ^ self.vectors[3], False)


if __name__ == '__main__':
	#Test Vectors
	key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" #os.urandom(16)
	input_data = ''.join(chr(i) for i in range(64)).encode('utf-8')

	test_vectors = ["310e0edd47db6f72", "fd67dc93c539f874", "5a4fa9d909806c0d", "2d7efbd796666785",
	"b7877127e09427cf", "8da699cd64557618", "cee3fe586e46c9cb", "37d1018bf50002ab",
	"6224939a79f5f593", "b0e4a90bdf82009e", "f3b9dd94c5bb5d7a", "a7ad6b22462fb3f4",
	"fbe50e86bc8f1e75", "903d84c02756ea14", "eef27a8e90ca23f7", "e545be4961ca29a1",
	"db9bc2577fcc2a3f", "9447be2cf5e99a69", "9cd38d96f0b3c14b", "bd6179a71dc96dbb",
	"98eea21af25cd6be", "c7673b2eb0cbf2d0", "883ea3e395675393", "c8ce5ccd8c030ca8",
	"94af49f6c650adb8", "eab8858ade92e1bc", "f315bb5bb835d817", "adcf6b0763612e2f",
	"a5c91da7acaa4dde", "716595876650a2a6", "28ef495c53a387ad", "42c341d8fa92d832",
	"ce7cf2722f512771", "e37859f94623f3a7", "381205bb1ab0e012", "ae97a10fd434e015",
	"b4a31508beff4d31", "81396229f0907902", "4d0cf49ee5d4dcca", "5c73336a76d8bf9a",
	"d0a704536ba93e0e", "925958fcd6420cad", "a915c29bc8067318", "952b79f3bc0aa6d4",
	"f21df2e41d4535f9", "87577519048f53a9", "10a56cf5dfcd9adb", "eb75095ccd986cd0",
	"51a9cb9ecba312e6", "96afadfc2ce666c7", "72fe52975a4364ee", "5a1645b276d592a1",
	"b274cb8ebf87870a", "6f9bb4203de7b381", "eaecb2a30b22a87f", "9924a43cc1315724",
	"bd838d3aafbf8db7", "0b1a2a3265d51aea", "135079a3231ce660", "932b2846e4d70666",
	"e1915f5cb1eca46c", "f325965ca16d629f", "575ff28e60381be5", "724506eb4c328a95"]

	for i in range(64):
		sip = siphash(key)
		out = sip.hash(input_data[:i])
		print(f"SipHash({input_data[:i].hex()})")
		assert out.hex() == test_vectors[i]
		print(f"{out.hex() == test_vectors[i]}: {out.hex()} == {test_vectors[i]} ")

	#sip = siphash(b'0123456789ABCDEF')
	#sip.vectors = [4925064773550298181, 2461839666708829781, 6579568090023412561, 3611922228250500171]
	#sip._sip_round(0x100000000000061)
	#print(f"v2: {sip.vectors}")

	#sip  = siphash(key)
	#output = sip.hash(b"\x00\x01\x02\x03\x04\x05\x06\x07")
	#print(f"sip({b"\x00\x01\x02\x03\x04\x05\x06\x07"}) = {output.hex()}")

	#Hash data
