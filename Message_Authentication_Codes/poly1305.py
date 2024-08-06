import sys
sys.path.append("..")

from cryptopals_lib import * 

#Info from http://loup-vaillant.fr/tutorials/poly1305-design
def poly1305_hash(key, message, output_size=16):
	#Set the mod p = 2^130-5
	p = 0x3fffffffffffffffffffffffffffffffb

	#Set some bits for r from spec and convert to little endian
	random = bytes_to_int(key[:16], False) & 0x0ffffffc0ffffffc0ffffffc0fffffff

	#Set secret part and convert to little endian
	secret = bytes_to_int(key[16:], False)

	hash_output = 0

	#Chunk the message into 128-bit ints
	for message_block in to_blocks(message, 16):
		#Set the first bit to 1 and convert to little endian
		message_int = bytes_to_int(message_block + bytes([1]), False)
		# Add the message into the hash accumulator
		hash_output += message_int
		# Multiply the hash by the random value taken from the input key
		hash_output *= random
		# Mod the value by 2^130-5 
		hash_output %= p
	
	#Finalize the hash by adding the secret derived from the key
	hash_output += secret
	#Set the output configurable size
	hash_output &= ((1 << output_size*8) -1)

	#Convert the little endian integer back into a bytestring
	return int_to_bytes(hash_output, False)

def poly1305(key, message, iv=None):
	#Generate IV if null
	if iv == None:
		iv = os.urandom(12)

	#Generate the Poly1305 key from the chacha keystream 
	poly_key = chacha_encrypt(iv, key, b'\x00' * 32)

	#Return the Randomly generated IV and message tag
	return iv, poly1305_hash(poly_key, message)

if __name__ == '__main__':

	#From https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
	key = bytes.fromhex("746869732069732033322d62797465206b657920666f7220506f6c7931333035")
	message = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
	tag = poly1305_hash(key, message)
	print(f"TAG: {tag.hex()}")
	#TAG: 49ec78090e481ec6c26b33b91ccc0307

	#From https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
	key = bytes.fromhex("746869732069732033322d62797465206b657920666f7220506f6c7931333035")
	message = bytes.fromhex("48656c6c6f20776f726c6421")
	tag = poly1305_hash(key, message)
	print(f"TAG: {tag.hex()}")
	#TAG: a6f745008f81c916a20dcc74eef2b2f0
