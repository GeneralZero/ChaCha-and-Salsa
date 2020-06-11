from cryptopals_lib import *

class SHA(object):
	def __init__(self):
		self.buffers = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

		self.round_constants = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
		
	def _set_message(self, message):
		#Convert to bytes if not already
		byte_message = bytearray(message)

		#Get Length shifted by 8 and limit to 64bit int
		input_length_data = asint64(len(byte_message) << 3)

		#Append 0x80 to the end of the message as a end of message byte
		byte_message.append(0x80)

		#Pad the data to a multable of 64 bytes when the 8 byte input_length_data is added 
		while len(byte_message) % 64 != 56:
			byte_message.append(0x00)

		#Append the length data to the message
		byte_message += int_to_bytes_length(input_length_data, 8)

		return byte_message

	def _hash_message_chunk(self, chunk):
		temp_buffers = self.buffers[:]

		#Create the start of the temp chunks
		temp_chunks = bytes_to_intarray(chunk, 4, byte_order="big")

		#Generate the rest of the chunks
		for index in range(16, 80):
			temp_chunks.append(shift_rotate_left(temp_chunks[index-3] ^ temp_chunks[index-8] ^ temp_chunks[index-14] ^ temp_chunks[index-16], 1))

		#First Rounds itteration
		for round_itteration in range(20):
			#print(round_itteration, temp_buffers)
			#Do Function F (b & c) ^ (~b & d)
			temp_value = fixedlen_xor((temp_buffers[1] & temp_buffers[2]), (~temp_buffers[1] & temp_buffers[3]))

			#Add Varables mod 32
			#print(shift_rotate_left(temp_buffers[0], 5), temp_value, temp_buffers[4], self.round_constants[0], temp_chunks[round_itteration])
			temp_value = asint32(shift_rotate_left(temp_buffers[0], 5) + temp_value + temp_buffers[4] + self.round_constants[0] + temp_chunks[round_itteration])

			#Swap values in to the new buffer
			temp_buffers = [temp_value, temp_buffers[0], shift_rotate_left(temp_buffers[1], 30), temp_buffers[2], temp_buffers[3]]

		for round_itteration in range(20, 40):
			#print(round_itteration, temp_buffers)
			#Do Function G b ^ c ^ d
			temp_value = fixedlen_xor(temp_buffers[1], fixedlen_xor(temp_buffers[2], temp_buffers[3]))

			#Add Varables mod 32
			temp_value = asint32(shift_rotate_left(temp_buffers[0], 5) + temp_value + temp_buffers[4] + self.round_constants[1] + temp_chunks[round_itteration])

			#Swap values in to the new buffer
			temp_buffers = [temp_value, temp_buffers[0], shift_rotate_left(temp_buffers[1], 30), temp_buffers[2], temp_buffers[3]]

		for round_itteration in range(40, 60):
			#print(round_itteration, temp_buffers)
			#Do Function H (b & c) ^ (b & d) ^ (c & d)
			temp_value = fixedlen_xor(fixedlen_xor((temp_buffers[1] & temp_buffers[2]), (temp_buffers[1] & temp_buffers[3])), (temp_buffers[2] & temp_buffers[3]))

			#Add Varables mod 32
			temp_value = asint32(shift_rotate_left(temp_buffers[0], 5) + temp_value + temp_buffers[4] + self.round_constants[2] + temp_chunks[round_itteration])

			#Swap values in to the new buffer
			temp_buffers = [temp_value, temp_buffers[0], shift_rotate_left(temp_buffers[1], 30), temp_buffers[2], temp_buffers[3]]

		for round_itteration in range(60, 80):
			#print(round_itteration, temp_buffers)
			#Do Function I b ^ c ^ d
			temp_value = fixedlen_xor(temp_buffers[1], fixedlen_xor(temp_buffers[2], temp_buffers[3]))

			#Add Varables mod 32
			temp_value = asint32(shift_rotate_left(temp_buffers[0], 5) + temp_value + temp_buffers[4] + self.round_constants[3] + temp_chunks[round_itteration])

			#Swap values in to the new buffer
			temp_buffers = [temp_value, temp_buffers[0], shift_rotate_left(temp_buffers[1], 30), temp_buffers[2], temp_buffers[3]]

		#Chunks are done with the round
		#Update the internal buffers with the new data
		self.buffers = [asint32(self.buffers[0] + temp_buffers[0]), 
						asint32(self.buffers[1] + temp_buffers[1]),
						asint32(self.buffers[2] + temp_buffers[2]),
						asint32(self.buffers[3] + temp_buffers[3]),
						asint32(self.buffers[4] + temp_buffers[4])]


	def hash(self, message):
		#Setup message with padding and length data
		byte_message = self._set_message(message)

		#Opperate on each of the 64 byte chunks
		for chunk in to_blocks(byte_message, 64):
			self._hash_message_chunk(chunk)

		#Convert Intagers to Byte string
		output = b""
		for x in self.buffers:
			output += (x).to_bytes(4, byteorder='big')

		
		return output
		
	def hash_digest(self, message):
		return self.hash(message).hex()

if __name__ == '__main__':
	testsha = SHA()
	print(testsha.hash_digest(b""))
	#da39a3ee5e6b4b0d3255bfef95601890afd80709

	testsha = SHA()
	print(testsha.hash_digest(b"a"))
	#86f7e437faa5a7fce15d1ddcb9eaeaea377667b8

	testsha = SHA()
	print(testsha.hash_digest(b"c7840924e344f6d3934999be91f1f079c759cfc1d7ebb38655b49415df9a1c67b9345d01c0c0aaacd51357f74e356d75fc7e22322637d54d43331b143e268b297eee06be41abefdd2b78cdc33a7f9372e9f4df44d0c5d3a981c7084b2cc6be181b13251f2151cc03d2b0c6d001c13105dd1d5bd7e3200696545ed7ed9c1dc2662fe34f35b8caffbb0466b129736fa4b0ad18e21297836814561cdeaba49b345b6f5e3717a322485acb01ba9af6fe085052bdd158ab930b80b0c96eb2fd28570e9c81579f304443a8c3e4c4e3c0968444acc65e000730b4399719936c7e141d40b6d721f4fa97254465a9ddf51f1e70ad340ad8cc27671fd8a28bda7ec2ce475ebf1819b448f8804c2a2df277ae613974c889a7dc0bfa42698e29e663e0d5591324221267fc5d3ff101e81afdb4f9fb4a40c025bbab9c5809bd297904e6ca3b8036cc4ead33ea28639803cac1a5a67572bbc7947254d15d8befd44e7125920ba5f6f6e87cf07e75e56ea47f3817ff35de2033652a5c9a797d44b811c6482a345d0201a3064b6dd9e6b86735c16efd34120a3adb3496fc52472175056bef762f76e93bd6e7253f4c2baaddeb7d2aa1ee187909fc842276021ce38c82ad57594eb416f80fa0804437a501b21e9f8643d6120b9c0ab5d7624e1c3354c473446757dd1c722f5703055598d16d2458b77defbab48b87ca205339e4417a4486958d96db"))
	#0a1a0fbb3c5bfd22f5fdfdd17c9bf2c9b1281fa4
