import hashlib
from cryptopals_lib import fixedlen_xor

def hmac(key, message, hash_function):
	#Get hash_function block_size
	block_size = getattr(hash_function(), 'block_size')

	# Check if key is longer than block size.
	if len(key) > block_size:
		# IF it is then hash the key. This makes the keysize the same as the output of the hashfunction
		key = hash_function(key).digest()

	# IF key is shorter
	if len(key) < block_size:
		# Pad the key to blocksize
		key = key + b"\x00" * (block_size - len(key))

	#print(key, len(key), block_size)

	# Create Keys
	o_key = fixedlen_xor(key, b"\x5c" * block_size)
	i_key = fixedlen_xor(key, b"\x36" * block_size)

	#Hash i_key and message
	tmp = hash_function(i_key + message)

	#Hash the o_key and the hashed output of above
	return hash_function(o_key + tmp.digest()).digest()


if __name__ == '__main__':
	test = hmac(b'key', b'some msg', hashlib.sha256)
	print(test.hex())
	#32885b49c8a1009e6d66662f8462e7dd5df769a7b725d1d546574e6d5d6e76ad