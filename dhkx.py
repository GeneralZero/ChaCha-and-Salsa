import secrets

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

if __name__ == '__main__':
	#Genearte User1 Keys
	user1_public_key, user1_private_key = generate_key_pair()

	#Generate User2 Keys
	user2_public_key, user2_private_key = generate_key_pair()

	#Generate Shared Secret
	user1_shared_secert = pow(user2_public_key["transmit_key"], user1_private_key["secret_exp"], user1_private_key["prime_mod"])
	user2_shared_secert = pow(user1_public_key["transmit_key"], user2_private_key["secret_exp"], user2_private_key["prime_mod"])

	assert user1_shared_secert == user2_shared_secert

