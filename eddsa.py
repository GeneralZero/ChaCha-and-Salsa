from ecc_lib import *
import hashlib
from cryptopals_lib import bytes_to_int, int_to_bytes


### EdDSA
def eddsa_sign(privateKey, curve_generator, message, hash_obj=hashlib.sha256):
	#Derive Information
	curve = curve_generator.curve
	order = curve.order
	public_key = curve_generator * privateKey

	#Generate a Random Number hashed from the private key and the message
	hashed_secret_key  = hash_obj(int_to_bytes(privateKey)).digest()
	hashed_message_int = bytes_to_int(hash_obj(hashed_secret_key + message).digest()) % order

	#Generate Random and make a new Point
	message_publickey = curve_generator * hashed_message_int

	#Calculate the hash of the public Information
	# Message_PublicKey | Sender_PublicKey | Message
	hash_output_int = bytes_to_int(hash_obj( message_publickey.compressed() + public_key.compressed() + message).digest()) % order

	#Generate S
	s = (hashed_message_int + ( hash_output_int * privateKey)) % order 

	return {"message_key":message_publickey.compressed(), "signature":s}


def eddsa_verify(public_key, message, signature_obj, curve_generator, hash_obj=hashlib.sha256):
	#Derive Information
	curve = curve_generator.curve
	order = curve.order
	message_publickey = Point(point_x=None, point_y=None, curve=curve_generator.curve).decompress(signature_obj["message_key"])

	#Calculate Point 1 from the signature["signature"] int
	test_point1 = curve_generator * signature_obj["signature"] 

	#Calculate the hash of the public Information
	# Message_PublicKey | Sender_PublicKey | Message
	hash_output_int = bytes_to_int(hash_obj( signature_obj["message_key"] + public_key.compressed() + message).digest()) % order

	#R' = (h * s1) * G + (r * s1) * pubKey
	test_point2 = (message_publickey + ( public_key * hash_output_int)) 

	#Because of the way this is checked there are two possible public keys. The one that is used and the negative point
	return test_point1 == test_point2

if __name__ == '__main__':
	message = b"Test Message"

	#Generate KeyPair
	privateKey, public_point = generate_KeyPair(Curve25519_Generator_Point)
	print(privateKey, public_point)

	#Generate Signature
	signature = eddsa_sign(privateKey, Curve25519_Generator_Point, message)
	print(signature)
	

	#Check Signature
	verify = eddsa_verify(public_point, message, signature, Curve25519_Generator_Point)
	print(verify)