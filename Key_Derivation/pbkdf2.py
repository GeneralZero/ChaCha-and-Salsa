import hashlib, sys
sys.path.append("..")

from cryptopals_lib import fixedlen_xor, int_to_bytes_length
from Message_Authentication_Codes.hmac import hmac

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


def pbkdf1(password, salt, itterations=1000, keylength=24, hashobj=hashlib.sha1):
	output_hash = hashobj(password + salt).digest()

	#Check if keylength is too big for hash function
	if len(output_hash) < keylength:
		raise Exception("Invalid length {} for hash function".format(keylength))

	#Do Loop for itterations
	for idx in range(itterations):
		output_hash = hashobj(output_hash).digest()

	#Return the hash with the correct size
	return output_hash[:keylength]



def pbkdf2(password, salt, itterations=1000, keylength=24, hashobj=hashlib.sha1):
	#Use the password as the HMAC key
	#mac = hmac(password, b"", hashobj)

	#digest_size = getattr(hashobj(), 'block_size')
	#print(digest_size)

	key = b""
	block_num = 1


	while len(key) < keylength:
		new_hash = hmac(password, (salt + int_to_bytes_length(block_num, 4)), hashobj)
		xor_data = new_hash

		print(xor_data)

		#-1 for itterations since we already did one
		for idx in range(itterations-1):
			#Generate new hash
			new_hash = hmac(password, new_hash, hashobj)

			#Xor hash with running total
			xor_data = fixedlen_xor(xor_data, new_hash)

		#Do XOR on array and add to key
		key += xor_data

		#Update block number
		block_num += 1

	return key[:keylength]


if __name__ == '__main__':
	#test = hmac(b'key', b'some msg', hashlib.sha256)
	#print(test)
	#32885b49c8a1009e6d66662f8462e7dd5df769a7b725d1d546574e6d5d6e76ad

	#print(pbkdf1(b'password', b'salt', 1, 20, hashlib.sha1).hex())
	#47e97e39e2b32b15eb9278e53f7bfca57f8e6b2c

	#hashedpassword = hashlib.sha1(b'password').digest()

	#print(pbkdf2(b'password', b'salt', 1, 20, hashlib.sha1).hex())
	#0c60c80f961f0e71f3a9b524af6012062fe037a6

	#print(pbkdf2(b'password', b'salt', 10000, 20, hashlib.sha1).hex())
	#print(pbkdf2(hashedpassword, b'salt', 10000, 20, hashlib.sha1).hex())
	#a2c2646186828474b754591a547c18f132d88d74



	import os, hashlib

	bytes_of_hex_password = (os.urandom(128).hex()).encode('utf_8')
	salt = os.urandom(32)

	hashedpassword = hashlib.sha256(bytes_of_hex_password).digest()

	print("Bytes of Hex of password: {}".format(hashedpassword.hex()))
	print("Hash of password:         {}".format(bytes_of_hex_password.hex()))

	print("PBKDF2 Hashed:    {}".format(pbkdf2(hashedpassword, salt, 100000,24, hashlib.sha256).hex()))
	print("PBKDF2 Origional: {}".format(pbkdf2(bytes_of_hex_password, salt, 100000, 24, hashlib.sha256).hex()))
