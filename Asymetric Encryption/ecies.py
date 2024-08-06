import os

from ecc_lib import *

from chacha import salsa_encrypt
from blake2 import Blake2 

def encrypt(recipiant_public_point, curve_point, message, hash_lib, symetric_enc_obj):
	#Generate a specific Message Key
	message_privateKey, message_public_point = generate_KeyPair(curve_point)

	#Use ECDH to get a shared key with the public Point and the message_PrivateKey
	# message_priv * recipiant_public_point = message_priv * recip_privateKey * Generator
	shared_key = message_privateKey * recipiant_public_point

	#Since ECDSA is a point Convert it into bytes
	bytes_shared_key = shared_key.compress()
	print(f"Shared Key: {bytes_shared_key}")

	#Map the Bytes into a random output using a Hash Function
	#This is the shared key for the Symetric Encryption
	hashed_shared_key = hash_lib(output_size=64).hash(bytes_shared_key)
	#print(hashed_shared_key, len(hashed_shared_key))

	#Create IV and use
	iv = os.urandom(16)
	cipher_text = symetric_enc_obj(iv, hashed_shared_key, message)

	return [iv, cipher_text, message_public_point]


def decrypt(recip_privateKey, message_publicKey, iv, cipher_text, hash_lib, symetric_enc_obj):
	#Use ECDH to get a shared key with the public Point and the message_PrivateKey
	# message_priv * recipiant_public_point = message_priv * recip_privateKey * Generator
	# recip_privateKey * message_publicKey = recip_privateKey * message_priv * Generator
	shared_key = recip_privateKey * message_publicKey

	#Since ECDSA is a point Convert it into bytes
	bytes_shared_key = shared_key.compress()
	print(f"Shared Key: {bytes_shared_key}")

	#Map the Bytes into a random output using a Hash Function
	#This is the shared key for the Symetric Encryption
	hashed_shared_key = hash_lib(output_size=64).hash(bytes_shared_key)
	#print(hashed_shared_key, len(hashed_shared_key))

	#Create IV and use
	plaintext = symetric_enc_obj(iv, hashed_shared_key, cipher_text)

	return plaintext



if __name__ == '__main__':
	message = b"Some plaintext for encryption"

	#Generate Private and Public Key Pair for the Recipiant
	recip_privateKey, recip_public_point = generate_KeyPair(Curve25519_Generator_Point)


	#For Encryption only need the Recipiants Public Key to encrypt
	iv, cipher_text, message_publicKey = encrypt(recip_public_point, Curve25519_Generator_Point, message, Blake2, salsa_encrypt)
	print(f"cipher_text: {cipher_text}")

	#Send message_publicKey, iv and cipher_text to recipiant


	plaintext = decrypt(recip_privateKey, message_publicKey, iv, cipher_text, Blake2, salsa_encrypt)
	print(f"Plaintext: {plaintext}")


