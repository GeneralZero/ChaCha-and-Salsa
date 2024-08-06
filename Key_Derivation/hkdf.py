#!/usr/bin/env python3
import hashlib, os, sys
sys.path.append("..")


from math import ceil
from Message_Authentication_Codes.hmac import hmac

def hmac_hash(key, message, hash_object):
	return hmac(key, message, hash_object)

def hkdf(hash_object, output_size, input_key, salt=b"", data=b""):
	"""Key derivation function"""
	hash_len = hash_object().digest_size
	temp = b""
	output = b""

	if len(salt) == 0:
		salt = bytes([0] * hash_len)
	key_output = hmac_hash(salt, input_key, hash_object)
	for i in range(ceil(output_size / hash_len)):
		temp = hmac_hash(key_output, temp + data + bytes([1 + i]), hash_object)
		output += temp
	return output[:output_size]

if __name__ == '__main__':
	test = hkdf(hashlib.sha512, 24, os.urandom(16))
	print(test.hex())
