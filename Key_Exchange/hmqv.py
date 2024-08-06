import hashlib, os, math, random, sys
sys.path.append("..")

from ecc_lib import *

from cryptopals_lib import bytes_to_int, int_to_bytes, secure_rand_between

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


	#HMQV uses a Hash of their own public_key and the other users random point
	#This is used to replace the Bar function from MQV
	alice_hash_output = hashlib.sha512(alice_random_point.compressed() + b"|" +  bob_public_point.compressed()).digest()
	alice_bar = bytes_to_int(alice_hash_output) % order
	bob_hash_output   = hashlib.sha512(bob_random_point.compressed() + b"|" +  alice_public_point.compressed()).digest()
	bob_bar = bytes_to_int(bob_hash_output) % order
	#print(f"Alice Bar: {alice_bar}")
	#print(f"Bob Bar: {bob_bar}")


	#Generate Signatures
	alice_signature = (alice_random + (alice_bar * alice_private_key)) % order
	bob_signature = (bob_random + (bob_bar * bob_private_key)) % order
	print(f"Alice Signature: {alice_signature}")
	print(f"Bob Signature:   {bob_signature}")


	#Key Exchange

	#Alice Side
	#Ja = cofactor * alice_signature * (bob_random_point + bar(bob_random_point) * bob_public_key_point)
	alice_side = bob_random_point + ( bob_bar * bob_public_point)
	alice_side = cofactor * (alice_signature * alice_side)


	#Bob side
	#Jb = cofactor * bob_signature * (alice_random_point + bar(alice_random_point) * alice_public_key_point)
	bob_side = alice_random_point + ( alice_bar * alice_public_point)
	bob_side = cofactor * (bob_signature * bob_side)

	print(alice_side)
	print(bob_side)


	assert alice_side == bob_side
