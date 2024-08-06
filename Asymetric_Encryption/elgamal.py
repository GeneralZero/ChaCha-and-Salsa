import secrets, sys
sys.path.append("..")

from cryptopals_lib import bytes_to_int, int_to_bytes

def generate_key_pair(prime=((1 << 1024) - 1093337), g=7):
	#generate a 1024 bit prime number for the Mod
	#prime_mod = generate_probable_prime(1024)
	prime_mod = prime

	#Genreate Secret Exponent
	secret_exp = 0
	while secret_exp < 2:
		secret_exp = secrets.randbelow(prime_mod-2)
	generator = g

	#Generate the Transmit key A = G^x % P
	transmit_key = pow(generator, secret_exp, prime_mod)

	return {"generator":generator, "prime_mod":prime_mod, "transmit_key": transmit_key}, {"generator":generator, "prime_mod":prime_mod, "secret_exp": secret_exp} 

def gen_random(low, high):
	random = 0
	while random < low:
		random = secrets.randbelow(high)

	return random

def encrypt_message(to_public_key, message):
	message = bytes_to_int(message)

	#Generate One Time Key
	ephemeral_key = gen_random(1, to_public_key["prime_mod"]-2)

	#Generate Ciphered Key = G^y % P
	ciphertext_ephemeral_key = pow(to_public_key["generator"], ephemeral_key, to_public_key["prime_mod"])

	#Generate Secret S = (G^x)^y %p
	shared_secret = pow(to_public_key["transmit_key"], ephemeral_key, to_public_key["prime_mod"])

	#Generate Ciphertext message c2 = (m*s) % p
	cipheretext_message = (message * shared_secret) % to_public_key["prime_mod"]

	return (ciphertext_ephemeral_key, cipheretext_message)


def decrypt_message(ephemeral_key_ciphertext, message_ciphertext, to_private_key):
	#Generate Shared Secret
	shared_secret = pow(ephemeral_key_ciphertext, to_private_key["secret_exp"], to_private_key["prime_mod"])

	#Mod inverse
	shared_secret_inverse = pow(shared_secret, -1, to_private_key["prime_mod"])

	#Decrypt Message
	return (message_ciphertext * shared_secret_inverse) % to_private_key["prime_mod"]



if __name__ == '__main__':
	message = b"Hello World"

	#Generate User1 Ephemeral Key
	public_key, private_key = generate_key_pair()


	#Message sent from User1 -> User2
	print("Message: {}".format(message))
	ephemeral_key_ciphertext, message_ciphertext = encrypt_message(public_key, message)
	print("Encrypted Message: {} {}".format(ephemeral_key_ciphertext, message_ciphertext))

	#Message decrypred by User2
	decrypted_int_message = decrypt_message(ephemeral_key_ciphertext, message_ciphertext, private_key)
	decrypted_message = int_to_bytes(decrypted_int_message)
	print("Decrypted Message: {}".format(decrypted_message))

	assert(message == decrypted_message)


