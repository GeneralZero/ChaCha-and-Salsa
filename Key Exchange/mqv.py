from ecc_lib import *
import hashlib, os, math, random
from cryptopals_lib import bytes_to_int, int_to_bytes, secure_rand_between


def bar(x, order):
	#Take the first L bits of the x Point and set the MSB
	l = math.ceil( (math.floor(math.log(order, 2)) + 1) / 2 )
	return ( x % pow(2, l) ) + pow(2, l)



if __name__ == '__main__':
	order = secp256k1_Generator_Point.curve.order
	cofactor = 1

	#Generate KeyPair Alice
	alice_private_key, alice_public_point = generate_KeyPair(secp256k1_Generator_Point)

	#Generate Alice random Point
	alice_random = random.getrandbits(256)
	alice_random_point = secp256k1_Generator_Point * alice_random

	print(alice_private_key, alice_public_point)


	#Generate KeyPair Bob
	bob_private_key, bob_public_point = generate_KeyPair(secp256k1_Generator_Point)
	print(bob_private_key, bob_public_point)

	#Generate Bob random Point
	bob_random = random.getrandbits(256)
	bob_random_point = secp256k1_Generator_Point * bob_random



	#Generate Signatures
	alice_signature = (alice_random + (bar(alice_random_point.x, order) * alice_private_key)) % order
	bob_signature = (bob_random + (bar(bob_random_point.x, order) * bob_private_key)) % order
	print(f"Alice Signature: {alice_signature}")
	print(f"Bob Signature:   {bob_signature}")


	#Key Exchange

	#Alice Side
	#Ja = cofactor * alice_signature * (bob_random_point + bar(bob_random_point) * bob_public_key_point)
	alice_side = bob_random_point + ( bar(bob_random_point.x, order) * bob_public_point)
	alice_side = cofactor * (alice_signature * alice_side)


	#Bob side
	#Jb = cofactor * bob_signature * (alice_random_point + bar(alice_random_point) * alice_public_key_point)
	bob_side = alice_random_point + ( bar(alice_random_point.x, order) * alice_public_point)
	bob_side = cofactor * (bob_signature * bob_side)

	print(alice_side)
	print(bob_side)


	assert alice_side == bob_side
