from Crypto.PublicKey import DSA

import secrets, hashlib
from cryptopals_lib import bytes_to_int, int_to_bytes

def gen_random(low, high):
	random = 0
	while random < low:
		random = secrets.randbelow(high)

	return random


def sign(private_key, message, hash_obj=hashlib.sha256):
	#Generate Hash of message
	message_hash = bytes_to_int(hash_obj(message).digest())

	#Genearte ints
	prime_mod, subgroup_order, generator = private_key.domain()
	secret_exp = private_key.x

	#init outputs
	random_output = 0
	signature = 0

	#check if r = 0
	while random_output == 0 or signature == 0:
		#Generate a Random Intager between 1, q-1
		random_int = gen_random(1, subgroup_order-1)
		
		#Compute (g^k mod P) mod q
		random_output = pow(generator, random_int, prime_mod) % subgroup_order

		#Compute Mod Inverse of k
		random_int_inverse = pow(random_int, -1, subgroup_order)

		#Compute Signature
		# s:= k^-1 (H(m) + x*r)) mod q
		signature = (random_int_inverse * (message_hash + (secret_exp * random_output))) % subgroup_order

	return random_output, signature


def verify(public_key, message, random_output, signature, hash_obj=hashlib.sha256):
	#Genearte ints
	prime_mod, subgroup_order, generator = public_key.domain()
	public_int = public_key.y

	#Generate Hash of message
	message_hash = bytes_to_int(hash_obj(message).digest())


	if random_output > 0 and random_output < (prime_mod-1) and signature > 0 and signature < (prime_mod-1):
		#Generate Mod inverse of signature
		inverse_signature = pow(signature, -1, subgroup_order)

		#Generate First part of the comparision
		exp_from_sig = (inverse_signature * message_hash) % subgroup_order
		compare_from_signature = pow(generator, exp_from_sig, prime_mod)

		#Generate Second part of Comparison
		exp_from_rand = (random_output * inverse_signature) % subgroup_order
		compare_from_rand = pow(public_int, exp_from_rand, prime_mod)

		compare_random = ((compare_from_signature * compare_from_rand) % prime_mod ) % subgroup_order


		return random_output == compare_random
	else:
		raise Exception("Invalid random_output or signature")


if __name__ == '__main__':
	# Create a new DSA key
	#public_key, private_key = generate_key_pair()
	key = DSA.generate(2048)
	#print("DSA Key: {}".format(private_key))

	# Hash the message
	message = b"Hello"

	#Sign the Message 
	rand_out, signature = sign(key, message, hashlib.sha256)
	print(f"rand_out: {hex(rand_out)}")
	print(f"sign:     {hex(signature)}")

	#Verify the Signature
	valid = verify(key, message, rand_out, signature, hash_obj=hashlib.sha256)
	print("Signatures are Valid: {}".format(valid))

