import hashlib, sys
sys.path.append("..")

from ecc_lib import *
from cryptopals_lib import bytes_to_int, int_to_bytes

### ECDSA
def ecdsa_sign(privateKey, curve_generator, message, hash_obj=hashlib.sha256):
	#Derive Information
	curve = curve_generator.curve
	order = curve.order

	#Hash the message
	hashed_message_int = bytes_to_int(hash_obj(message).digest()) % order

	#Generate Random and make a new Point
	message_privatekey, message_publickey = generate_KeyPair(curve_generator)

	#Get Inverse of the message_privatekey
	inverse_message_privatekey = modinv(message_privatekey, order) 

	#Generate S
	# s = (k^-1 * (hash + (private_mult * x_point_k)) % order ) % order
	s = (inverse_message_privatekey * (hashed_message_int + ( privateKey * message_publickey.x)) % order ) % order

	return {"message_x":message_publickey.x, "signature":s}


def ecdsa_verify(public_key, message, signature_obj, curve_generator, hash_obj=hashlib.sha256):
	#Derive Information
	curve = curve_generator.curve
	order = curve.order

	#Hash message
	hashed_message_int = bytes_to_int(hash_obj(message).digest()) % order

	#Use the inverse of the signature
	inverse_signature = modinv(signature_obj["signature"], order) 
	
	#R' = (h * s1) * G + (r * s1) * pubKey
	test_point = (inverse_signature * hashed_message_int) * curve_generator + (((signature_obj["message_x"] * inverse_signature) % order) * public_key)

	#Because of the way this is checked there are two possible public keys. The one that is used and the negative point
	return test_point.x == signature_obj["message_x"]


### Deterministic ECDSA
def deterministic_ecdsa_sign(privateKey, curve_generator, message, hash_obj=hashlib.sha256):
	#Derive Information
	curve = curve_generator.curve
	order = curve.order
	public_key = privateKey * curve_generator

	#Hash the message
	hashed_message = hash_obj(curve.name.encode('utf-8') + public_key.compressed() + message).digest()
	hashed_message_int = bytes_to_int(hashed_message)

	#Generate Random and make a new Point
	message_random_int = bytes_to_int(hash_obj(hashed_message + int_to_bytes(privateKey)).digest())
	message_publickey = curve_generator * message_random_int

	#Get Inverse of the message_privatekey
	inverse_message_privatekey = modinv(message_random_int, order) 

	#Generate S
	# s = (k^-1 * (hash + (private_mult * x_point_k)) % order ) % order
	s = (inverse_message_privatekey * (hashed_message_int + ( privateKey * message_publickey.x)) % order ) % order

	return {"message_x":message_publickey.x, "signature":s}


def deterministic_ecdsa_verify(public_key, message, signature_obj, curve_generator, hash_obj=hashlib.sha256):
	#Derive Information
	curve = curve_generator.curve
	order = curve.order

	#Hash the message
	hashed_message = hash_obj(curve.name.encode('utf-8') + public_key.compressed() + message).digest()
	hashed_message_int = bytes_to_int(hashed_message)

	#Use the inverse of the signature
	inverse_signature = modinv(signature_obj["signature"], order) 
	
	#R' = (h * s1) * G + (r * s1) * pubKey
	test_point = (inverse_signature * hashed_message_int) * curve_generator + (((signature_obj["message_x"] * inverse_signature) % order) * public_key)

	#Because of the way this is checked there are two possible public keys. The one that is used and the negative point
	return test_point.x == signature_obj["message_x"]


if __name__ == '__main__':
	message = b"Test Message"

	#Generate KeyPair
	privateKey, public_point = generate_KeyPair(Curve25519_Generator_Point)
	print(privateKey, public_point)

	#Message Information
	#Hash Library

	#### ECDSA

	#Create Signature
	signature = ecdsa_sign(privateKey, Curve25519_Generator_Point, message)
	print(signature)

	#Check Signature
	verify = ecdsa_verify(public_point, message, signature, Curve25519_Generator_Point)
	print(verify)

	#Test Duplicate Signature
	signature["signature"] = Curve25519_Generator_Point.curve.order - signature["signature"]
	verify = ecdsa_verify(public_point, message, signature, Curve25519_Generator_Point)
	print(verify)


	#### Deterministic ECDSA
	
	#Create Signature
	signature = deterministic_ecdsa_sign(privateKey, Curve25519_Generator_Point, message)
	print(signature)

	#Check Signature
	verify = deterministic_ecdsa_verify(public_point, message, signature, Curve25519_Generator_Point)
	print(verify)
