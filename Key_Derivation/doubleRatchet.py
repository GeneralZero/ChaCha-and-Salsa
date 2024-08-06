from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import json, os, base64

class Signal_Server():
	def __init__(self):
		### x3DH Varables
		self.idenity_database = {}
		self.idenity_database_sign = {}

		self.preKey_database = {}
		self.onetime_database = {}
		self.info = b"Signal_Server"

		### Double Ratchet Variables
		self.dh_ratchet_keys = {}
	
	def registerUser(self, username, idenity_key, idenity_key_sign):
		self.idenity_database[username] = idenity_key
		self.idenity_database_sign[username] = idenity_key_sign

	def getUsersDoubleRatchetKey(self, username):
		if username in self.dh_ratchet_keys:
				return self.dh_ratchet_keys[username]
		return None

	def getUsersIdenityKey(self, username):
		return self.idenity_database[username]

	def getUsersIdenitySigningKey(self, username):
		return self.idenity_database_sign[username]

	def getUsersPreKey(self, username):
		return self.preKey_database[username]

	def getUserOneTimeKey(self, username):
		#Return then remove key
		return self.onetime_database[username].pop(0)

	def updateUsersDoubleRatchetKey(self, src_username, double_ratchet_key):
		if src_username not in self.dh_ratchet_keys:
			self.dh_ratchet_keys[src_username] = {}
		self.dh_ratchet_keys[src_username] = double_ratchet_key

	def updateUserPreKey(self, username, preKey_bytes, signature):
		idenity_key = Ed448PublicKey.from_public_bytes(self.idenity_database_sign[username])

		if idenity_key.verify(signature, preKey_bytes):
			print("[-] Signature doesn't match the Prekey. Either Bad Signature, Wrong Key, wrong username")
			return False
		else:
			#print("[+] Signature Accepted")
			self.preKey_database[username] = {"key": preKey_bytes, "signature": signature}
			return True

	def addOneTimePreKey(self, username, keys_bytes):
		#Check from the correct User???
		if username not in self.onetime_database:
			self.onetime_database[username] = []
		self.onetime_database[username].append(keys_bytes)
			

class UserKDFs():
	def __init__(self, hash_obj=hashes.SHA512()):
		self.secret_length = 32
		self.hash_obj = hash_obj
		# Needs to be the same for each user
		# This is the shared secret for the x3DH
		self.kdfchain_root_keys = {}
		self.kdfchain_sending_keys = {}
		self.kdfchain_receiving_keys = {}

		self.kdfchain_x448_key = X448PrivateKey.generate()

		#Setup KDF Chains
		#DH shared key secrets are used for input to the root KDF Chain
		self.root_kdf_chains = {}
		#The root KDF Chain outputs are used as KDF keys for the sending and receiving chains
		#Each incoming/outgoing message advances the chain. The outputs are used for the Symmetric Encryption/Decryption for each message
		self.sending_kdf_chains = {}
		self.receiving_kdf_chains = {}


		#Initialize the Root Chain
	def ratchetChain(self, chain, username, dh_shared_secret=b""):
		if chain != "root" and dh_shared_secret != b"":
			raise ValueError(f"DH_secret only accepted on the root chain")
			return

		elif chain == "root":
			output = HKDF(algorithm=self.hash_obj, length=self.secret_length*2+12, salt=b"", info=b"").derive(self.kdfchain_root_keys[username] + dh_shared_secret)
			#Update RootKDF and return the rest of the output
			self.kdfchain_root_keys[username], ret = output[:self.secret_length], output[self.secret_length:]

		elif chain == "sending":
			output = HKDF(algorithm=self.hash_obj, length=self.secret_length*2+12, salt=b"", info=b"").derive(self.kdfchain_sending_keys[username])
			#Update SendingKDF and return the rest of the output
			self.kdfchain_sending_keys[username], ret = output[:self.secret_length], output[self.secret_length:]

		elif chain == "receiving":
			output = HKDF(algorithm=self.hash_obj, length=self.secret_length*2+12, salt=b"", info=b"").derive(self.kdfchain_receiving_keys[username])
			#Update RecievingKDF and return the rest of the output
			self.kdfchain_receiving_keys[username], ret = output[:self.secret_length], output[self.secret_length:]

		else:
			raise ValueError(f"{chain} is not a valid Chain")
			return

		return ret


	def initUserKDFs(self, username, sending=True, inital_shared_secret=None, public_key=None):
		#If inital_shared_secret is set then initialize the Chains as Symmetric Ratchet
		if inital_shared_secret != None and public_key != None:
			#Use the x3DH shared secret from the username to generate the initial RootKDF
			self.kdfchain_root_keys[username] = inital_shared_secret

			#Ratchet the Root KDF to initialize the Receive and Send Chains
			key1 = self.ratchetChain("root", username)[:self.secret_length]
			key2 = self.ratchetChain("root", username)[:self.secret_length]

			#If sending then update the sending Keys first
			if sending:
				self.kdfchain_sending_keys[username], self.kdfchain_receiving_keys[username] = key1, key2
				#print(f"Sending::initUserKDFs::SEM sending_keys[{username}]: {self.kdfchain_sending_keys[username].hex()}")
				#print(f"Sending::initUserKDFs::SEM receiving_keys[{username}]: {self.kdfchain_receiving_keys[username].hex()}")

				# Should only Trigger on an initialization sending
				dh_shared_secret = self.kdfchain_x448_key.exchange(public_key)
				#print(f"Sending::initUserKDFs::DH initial dh_shared_secret[{username}]: {dh_shared_secret.hex()}")

				#Update Root Ratchet with dh_shared_secret and update the receiving chain
				self.kdfchain_sending_keys[username] = self.ratchetChain("root", username, dh_shared_secret)[:self.secret_length]
				#print(f"Sending::initUserKDFs::DH sending_keys[{username}]: {self.kdfchain_sending_keys[username].hex()}")

			else:
				self.kdfchain_receiving_keys[username], self.kdfchain_sending_keys[username] = key1, key2
				#print(f"Receiving::initUserKDFs::SEM sending_keys[{username}]: {self.kdfchain_sending_keys[username].hex()}")
				#print(f"Receiving::initUserKDFs::SEM receiving_keys[{username}]: {self.kdfchain_receiving_keys[username].hex()}")
				


		#If the public key is also available do DH Ratchet 
		if not sending:
			dh_shared_secret = self.kdfchain_x448_key.exchange(public_key)

			#Update Root Ratchet with dh_shared_secret and update the sending chain
			self.kdfchain_receiving_keys[username] = self.ratchetChain("root", username, dh_shared_secret)[:self.secret_length]
			#print(f"Receiving::initUserKDFs::DH receiving_keys[{username}]: {self.kdfchain_receiving_keys[username].hex()}")


			#Update the Sending Ratchet
			#Create and send keys to the server
			self.kdfchain_x448_key = X448PrivateKey.generate()

			#Get the dh_shared_secret for the sending 
			dh_shared_secret = self.kdfchain_x448_key.exchange(public_key)
			#print(f"Receiving::initUserKDFs::DH new dh_shared_secret[{username}]: {dh_shared_secret.hex()}")

			#Update Root Ratchet with dh_shared_secret
			#Set the sending_key for user
			self.kdfchain_sending_keys[username] = self.ratchetChain("root", username, dh_shared_secret)[:self.secret_length]
			#print(f"Receiving::initUserKDFs::DH sending_keys[{username}]: {self.kdfchain_sending_keys[username].hex()}")




		
class Signal_User(object):
	def __init__(self, username, signal_server):
		self.username = username
		#Add the Signal Server to the user so You don't have to pass it through to all of the functions
		self.signal_server = signal_server


		### 3DH Specific Variables
		self.idenity_private_key_sign = Ed448PrivateKey.generate()
		#The Ed448 Private Key is 57 bits long while the x448 is 56 bits long
		#https://crypto.stackexchange.com/questions/99974/curve448-can-ed448-key-material-be-reused-for-x448
		# So we generate the x448 from the Ed448 key
		digest = hashes.Hash(hashes.SHAKE256(56))
		digest.update(self.idenity_private_key_sign.private_bytes_raw())
		x488_key = digest.finalize()
		self.idenity_private_key = X448PrivateKey.from_private_bytes(x488_key)

		self.private_pre_key = X448PrivateKey.generate()
		self.one_time_private_keys = []
		#Lets Generate 5 Prekeys
		for x in range(5):
			self.one_time_private_keys.append(X448PrivateKey.generate())


		### Double Ratchet Specific Variables
		self.users_ratchet = UserKDFs()
		self.dh_ratchet_cache = {}

	def send_RatchetKeyToSignalServer(self):
		self.signal_server.updateUsersDoubleRatchetKey(self.username, self.users_ratchet.kdfchain_x448_key.public_key().public_bytes_raw())

	def send_registerUser(self):
		self.signal_server.registerUser(self.username, self.idenity_private_key.public_key().public_bytes_raw(), self.idenity_private_key_sign.public_key().public_bytes_raw())

	def send_PreKeyToSignalServer(self):
		#Get Public Key
		public_Pre_Key = self.private_pre_key.public_key() 

		signature = self.idenity_private_key_sign.sign(public_Pre_Key.public_bytes_raw())

		#Send to Server
		self.signal_server.updateUserPreKey(self.username, public_Pre_Key.public_bytes_raw(), signature)


	def send_OneTimeKeysToSignalServer(self):
		for key in self.one_time_private_keys:
			key_bytes = key.public_key().public_bytes_raw()
			self.signal_server.addOneTimePreKey(self.username, key_bytes)

	def _generate3DHSecretKey_sender(self, username):
		#Lets get the required Data from the servers and check signatures
		dst_idenity_key = X448PublicKey.from_public_bytes(self.signal_server.getUsersIdenityKey(username))

		dst_idenity_sign_key = Ed448PublicKey.from_public_bytes(self.signal_server.getUsersIdenitySigningKey(username))
		dst_prekey_and_signature = self.signal_server.getUsersPreKey(username)
		dst_prekey = X448PublicKey.from_public_bytes(dst_prekey_and_signature["key"])
		dst_signature = dst_prekey_and_signature["signature"]

		#Generate Ephemeral Key for the rest of the Key generation
		self.ephemeral_3dh_key = X448PrivateKey.generate()

		dst_one_time_key = X448PublicKey.from_public_bytes(self.signal_server.getUserOneTimeKey(username))

		#Check that the signature is correct for that key
		if dst_idenity_sign_key.verify(dst_signature, dst_prekey_and_signature["key"]):
			print("[-] Signature doesn't match the Prekey. Either Bad Signature, Wrong Key, wrong username")
			return False

		#Generate the 4 DH keys and generate secret
		# DH1 = Alice Identity Key, Bob's Signed Pre_key
		#Now that we have checked that the server did not give us the wrong user key Lets continue
		dh1 = self.idenity_private_key.exchange(dst_prekey)


		#DH2 = Alice's Ephemeral Key, Bob's Identity Key
		#Alice Generates a new Key for this exchange on the fly
		dh2 = self.ephemeral_3dh_key.exchange(dst_idenity_key)


		#DH3 = Alice's Ephemeral Key, Bob's Signed Pre_key
		dh3 = self.ephemeral_3dh_key.exchange(dst_prekey)


		#DH4 = Alice's Ephemeral Key, Bob's One Time Key
		dh4 = self.ephemeral_3dh_key.exchange(dst_one_time_key)

		return self._generate3DHSecretKey(dh1, dh2, dh3, dh4)


	def _generate3DHSecretKey(self, dh1, dh2, dh3, dh4):
		if self.idenity_private_key is X448PrivateKey:
			pre_hash_bytes = 57*b"\xFF"
			hash_obj = HKDF(algorithm=hashes.SHA512(), length=64, salt=(64*b"\x00"), info=b"")
		else:
			pre_hash_bytes = 32*b"\xFF"
			hash_obj = HKDF(algorithm=hashes.SHA256(), length=32, salt=(32*b"\x00"), info=b"")

		secret_key = hash_obj.derive(pre_hash_bytes + dh1 + dh2 + dh3 + dh4)
		return secret_key

	def send_message(self, message, username):
		#Check if Signal Server has a Ratchet key for this User
		dst_ratchet_DH = X448PublicKey.from_public_bytes(self.signal_server.getUsersDoubleRatchetKey(username))
		#print(f"{self.username}::send_message: Get Ratchet Key From Server: {self.signal_server.getUsersDoubleRatchetKey(username).hex()}")
		#for x in self.dh_ratchet_cache:
		#	print(f"    {x}: {self.dh_ratchet_cache[x].public_bytes_raw().hex()}")

		#Only add the x3DH information if needed
		#Make sure to save the old dh key to add to the aad
		aad = {"src_idenity_key":self.idenity_private_key.public_key().public_bytes_raw().hex(),
		"src_ratchet_key": self.users_ratchet.kdfchain_x448_key.public_key().public_bytes_raw().hex(), "src_username": self.username,
		"dst_username": username, "server_info": self.signal_server.info.decode('ascii')}

		#First time seeing this user do x3DH
		if username not in self.dh_ratchet_cache:
			#Check if already done x3dh. If not do it
			#Initialize Ratchets knowing x3dh is done
			dh_secret_key = self._generate3DHSecretKey_sender(username)
			#print(f"{self.username}::send_message: finish 3xDH dh_secret_key: {dh_secret_key.hex()}")

			#Add x3DH to aad
			aad["src_ephemeral_key"] = self.ephemeral_3dh_key.public_key().public_bytes_raw().hex()

			#Init Ratchets
			self.users_ratchet.initUserKDFs(username, sending=True, inital_shared_secret=dh_secret_key, public_key=dst_ratchet_DH)
			print("Sending After Ratchet DH")
			#Update DH Ratchet Cache
			self.dh_ratchet_cache[username] = dst_ratchet_DH
			#Only update DH key when sending a message to another user
			self.send_RatchetKeyToSignalServer()
			#print(f"{self.username}::send_message: send to server Ratchet Key: {self.users_ratchet.kdfchain_x448_key.public_key().public_bytes_raw().hex()}")


		elif dst_ratchet_DH != self.dh_ratchet_cache[username]:
			#Destiation's Ratchet DH key has been updated Update Ratchet
			self.users_ratchet.initUserKDFs(username, sending=True, public_key=dst_ratchet_DH)
			print("Sending After Ratchet DH")
			#Update DH Ratchet Cache
			self.dh_ratchet_cache[username] = dst_ratchet_DH
			#Only update DH key when sending a message to another user
			self.send_RatchetKeyToSignalServer()
			#print(f"{self.username}::send_message: send to server Ratchet Key: {self.users_ratchet.kdfchain_x448_key.public_key().public_bytes_raw().hex()}")

		print(f"{self.username}::send_message: sending_key: {self.users_ratchet.kdfchain_sending_keys[username].hex()}")
		print(f"{self.username}::send_message: receiving_key: {self.users_ratchet.kdfchain_receiving_keys[username].hex()}")


		#Get message_sending Key from the ratchet
		output = self.users_ratchet.ratchetChain("sending", username)
		sending_key, nonce = output[:self.users_ratchet.secret_length], output[self.users_ratchet.secret_length:]
		#print(f"{self.username}::send_message: Encrypt with sending_key: {sending_key.hex()}, nonce: {nonce.hex()}")

		#Encrypt and return all information
		return self._AADAndEncryptMessage(sending_key, nonce, message, username, json.dumps(aad).encode('ascii'))



	def _AADAndEncryptMessage(self, secret_key, nonce, message, username, aad_bytes):
		chacha = ChaCha20Poly1305(secret_key)
		cyphertext = chacha.encrypt(nonce, message, aad_bytes)

		return {"aad":aad_bytes, "cyphertext": cyphertext}

	def receiveMessage(self, message):
		#Extract Information from message
		aad, cyphertext = [json.loads(message["aad"]), message["cyphertext"]]

		src_username, dst_username, server_info = [aad["src_username"], aad["dst_username"], aad["server_info"]]
		src_ratchet_key_bytes, src_idenity_key_bytes, = [bytes.fromhex(aad["src_ratchet_key"]), bytes.fromhex(aad["src_idenity_key"])]


		src_idenity_key = X448PublicKey.from_public_bytes(src_idenity_key_bytes)
		src_ratchet_key = X448PublicKey.from_public_bytes(src_ratchet_key_bytes)

		#Init Ratchets
		#First time seeing this user do x3DH
		if src_username not in self.dh_ratchet_cache:
			### Start x3DH for the Recipient
			src_ephemeral_key = X448PublicKey.from_public_bytes(bytes.fromhex(aad["src_ephemeral_key"]))

			#Generate DH1
			# DH1 = Src Idenity Key, Dst Signed Pre_key
			dh1 = self.private_pre_key.exchange(src_idenity_key)

			#Generate DH2
			#DH2 = Src Ephemeral Key, Dst Identity Key
			dh2 = self.idenity_private_key.exchange(src_ephemeral_key)

			#Generate DH3
			#DH3 = Src Ephemeral Key, Dst Signed Pre_key
			dh3 = self.private_pre_key.exchange(src_ephemeral_key)

			#Generate DH4
			#DH4 = Src Ephemeral Key, Dst One Time Key
			message_one_time_priv_key = self.one_time_private_keys.pop(0)
			dh4 = message_one_time_priv_key.exchange(src_ephemeral_key)

			#Generate Secret Key
			dh_shared_secret = self._generate3DHSecretKey(dh1, dh2, dh3, dh4)
			print(f"{self.username}::receiveMessage: dh_shared_secret: {dh_shared_secret.hex()}")

			#Init Ratchets
			self.users_ratchet.initUserKDFs(src_username, sending=False, inital_shared_secret=dh_shared_secret, public_key=src_ratchet_key)
			print("Receiving After Ratchet DH")
			#Update DH Ratchet Cache
			self.dh_ratchet_cache[src_username] = src_ratchet_key
			#Dont update signal server when receiving a message. Only when sending a message
			#self.send_RatchetKeyToSignalServer()

		elif src_ratchet_key != self.dh_ratchet_cache[src_username]:
			#Destination's Ratchet DH key has been updated Update Ratchet
			self.users_ratchet.initUserKDFs(src_username, sending=False, public_key=src_ratchet_key)
			print("Receiving After Ratchet DH")
			#Update DH Ratchet Cache
			self.dh_ratchet_cache[src_username] = src_ratchet_key
			#Dont update signal server when receiving a message. Only when sending a message
			#self.send_RatchetKeyToSignalServer()

		print(f"{self.username}::receiveMessage: sending_key: {self.users_ratchet.kdfchain_sending_keys[src_username].hex()}")
		print(f"{self.username}::receiveMessage: receiving_key: {self.users_ratchet.kdfchain_receiving_keys[src_username].hex()}")

		#Get message_sending Key from the ratchet
		output = self.users_ratchet.ratchetChain("receiving", src_username)
		receiving_key, nonce = output[:self.users_ratchet.secret_length], output[self.users_ratchet.secret_length:]



		#Decrypt and Verify Cypher text
		chacha = ChaCha20Poly1305(receiving_key)
		return chacha.decrypt(nonce, cyphertext, message["aad"])


if __name__ == '__main__':
	#Generate Server
	signal_server = Signal_Server()

	#Generate Users
	alice = Signal_User("alice", signal_server)
	bob = Signal_User("bob", signal_server)

	#Setup Users with the server
	alice.send_registerUser()
	#x3DH Initialization
	alice.send_PreKeyToSignalServer()
	alice.send_OneTimeKeysToSignalServer()
	#DH Ratchet Key Initialization
	alice.send_RatchetKeyToSignalServer()

	bob.send_registerUser()
	#x3DH Initialization
	bob.send_PreKeyToSignalServer()
	bob.send_OneTimeKeysToSignalServer()
	#DH Ratchet Key Initialization
	bob.send_RatchetKeyToSignalServer()


	#Test 5 Messages from a single user
	for x in range(5):
		encrypted_message = alice.send_message(b"Test Message 12345", "bob")
		print()
		print(f"Message Received: {bob.receiveMessage(encrypted_message)}")
		print()

	print()

	# Test 5 Ping Pong
	for x in range(5):
		encrypted_message = bob.send_message(b"Test Message 12345", "alice")
		print()
		print(f"Message Received: {alice.receiveMessage(encrypted_message)}")
		print()

		encrypted_message = alice.send_message(b"Test Message 12345", "bob")
		print()
		print(f"Message Received: {bob.receiveMessage(encrypted_message)}")
		print()

	#Test 5 Messages from a other user
	for x in range(5):
		encrypted_message = bob.send_message(b"Test Message 12345", "alice")
		print()
		print(f"Message Received: {alice.receiveMessage(encrypted_message)}")
		print()

	print()
