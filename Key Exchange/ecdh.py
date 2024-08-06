from ecc_lib import *


if __name__ == '__main__':

	#### Setup
	#User1 Generates their Private Public KeyPair
	privateKey1, public_point1 = generate_KeyPair(Curve25519_Generator_Point)
	print(privateKey1, public_point1)

	#User2 Generates their Private Public KeyPair
	privateKey2, public_point2 = generate_KeyPair(Curve25519_Generator_Point)
	print(privateKey2, public_point2)

	#### Exchange Data

	# User1 recives User2's Public Key

	# User2 recives User1's Public Key


	#### Key Generation

	#User1 Takes their Private Key and Multiplies it by User2's Public Key
	user1_shared_key = privateKey1 * public_point2


	#User2 Takes their Private Keu and multiplies it by User1's Public Key
	user2_shared_key = privateKey2 * public_point1


	#### Assurange that the shared key is the same

	#print(user2_shared_key, user1_shared_key)
	assert user1_shared_key == user2_shared_key