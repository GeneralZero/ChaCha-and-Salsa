from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import json, os, base64

class Signal_Server(object):
	"""docstring for Signal_Server"""
	def __init__(self):
		self.idenity_database = {}
		self.idenity_database_sign = {}
		self.preKey_database = {}
		self.onetime_database = {}
		self.info = b"Signal_Server"
	
	def registerUser(self, username, idenity_key, idenity_key_sign):
		self.idenity_database[username] = X448PublicKey.from_public_bytes(idenity_key)
		self.idenity_database_sign[username] = Ed448PublicKey.from_public_bytes(idenity_key_sign)

	def getUsersIdenityKey(self, username):
		return self.idenity_database[username].public_bytes_raw()

	def getUsersIdenitySigningKey(self, username):
		return self.idenity_database_sign[username].public_bytes_raw()

	def getUsersPreKey(self, username):
		return self.preKey_database[username]

	def getUserOneTimeKey(self, username):
		#Return then remove key
		return self.onetime_database[username].pop(0)

	def updateUserPreKey(self, username, preKey_bytes, signature):
		idenity_key = self.idenity_database_sign[username]

		if idenity_key.verify(signature, preKey_bytes):
			print("[-] Signature does't match the Prekey. Either Bad Signature, Wrong Key, wrong username")
			return False
		else:
			print("[+] Signature Accepted")
			self.preKey_database[username] = {"key": preKey_bytes, "signature": signature}
			return True

	def addOneTimePreKey(self, username, keys_bytes):
		#Check from the correct User???
		if username not in self.onetime_database:
			self.onetime_database[username] = []
		self.onetime_database[username].append(keys_bytes)
			

		
class Signal_User(object):
	"""docstring for Signal_User"""
	def __init__(self, username, signal_server):
		self.username = username
		self.idenity_private_key = None
		self.idenity_private_key_sign = None
		self.private_pre_key = None
		self.one_time_private_keys = []

		#Add the Signal Server to the user so You dont have to pass it through to all of the functions
		self.signal_server = signal_server

		self._generateKeys()

	def _generateKeys(self):
		self.idenity_private_key_sign = Ed448PrivateKey.generate()

		#The Ed448 Private Key is 57 bits long while the x448 is 56 bits long
		#https://crypto.stackexchange.com/questions/99974/curve448-can-ed448-key-material-be-reused-for-x448
		# So we generate the x448 from the Ed448 key
		digest = hashes.Hash(hashes.SHAKE256(57))
		digest.update(self.idenity_private_key_sign.private_bytes_raw())
		x488_key = digest.finalize()
		#print(x488_key)
		self.idenity_private_key = Ed448PrivateKey.from_private_bytes(x488_key)


		self.idenity_private_key = X448PrivateKey.generate()
		self.private_pre_key = X448PrivateKey.generate()

		#Lets Generate 5 Prekeys
		for x in range(5):
			self.one_time_private_keys.append(X448PrivateKey.generate())

	def registerUser(self):
		self.signal_server.registerUser(self.username, self.idenity_private_key.public_key().public_bytes_raw(), self.idenity_private_key_sign.public_key().public_bytes_raw())

	def generateEphemeralKey(self):
		self.ephemeral_key = X448PrivateKey.generate()

	def send_PreKeyToSignalServer(self):
		#Get Public Key
		public_Pre_Key = self.private_pre_key.public_key() 

		signature = self.idenity_private_key_sign.sign(public_Pre_Key.public_bytes_raw())

		#Send to Server
		self.signal_server.updateUserPreKey(self.username, public_Pre_Key.public_bytes_raw(), signature)

	def generateDH1_sender(self, username):
		#Get Destination User's Signed Public Key

		dst_idenity_sign_key = Ed448PublicKey.from_public_bytes(self.signal_server.getUsersIdenitySigningKey(username))

		dst_prekey_and_signature = self.signal_server.getUsersPreKey(username)

		#Check that the signature is correct for that key
		if dst_idenity_sign_key.verify(dst_prekey_and_signature["signature"], dst_prekey_and_signature["key"]):
			print("[-] Signature does't match the Prekey. Either Bad Signature, Wrong Key, wrong username")
			return False
		
		#Now that we have checked that the server did not give us the wrong user key Lets continue
		dst_prekey = X448PublicKey.from_public_bytes(dst_prekey_and_signature["key"])
		return self.idenity_private_key.exchange(dst_prekey)

	def generateDH2_sender(self, username):
		#Get Destination User's Signed Public Key
		dst_idenity_key = X448PublicKey.from_public_bytes(self.signal_server.getUsersIdenityKey(username))

		#Generate Ephemeral Key for the rest of the Key generation
		self.generateEphemeralKey()

		return self.ephemeral_key.exchange(dst_idenity_key)

	def generateDH3_sender(self, username):
		#Get Destination User's Signed Public Key

		dst_idenity_sign_key = Ed448PublicKey.from_public_bytes(self.signal_server.getUsersIdenitySigningKey(username))

		dst_prekey_and_signature = self.signal_server.getUsersPreKey(username)

		#Check that the signature is correct for that key
		if dst_idenity_sign_key.verify(dst_prekey_and_signature["signature"], dst_prekey_and_signature["key"]):
			print("[-] Signature does't match the Prekey. Either Bad Signature, Wrong Key, wrong username")
			return False
		
		#Now that we have checked that the server did not give us the wrong user key Lets continue
		dst_prekey = X448PublicKey.from_public_bytes(dst_prekey_and_signature["key"])
		return self.ephemeral_key.exchange(dst_prekey)

	def generateDH4_sender(self, username):
		#Get Destination User's Signed Public Key
		dst_idenity_key = X448PublicKey.from_public_bytes(self.signal_server.getUsersIdenityKey(username))
		dst_one_time_key = X448PublicKey.from_public_bytes(self.signal_server.getUserOneTimeKey(username))

		return self.ephemeral_key.exchange(dst_one_time_key)


	def send_OneTimeKeysToSignalServer(self):
		for key in self.one_time_private_keys:
			key_bytes = key.public_key().public_bytes_raw()
			self.signal_server.addOneTimePreKey(self.username, key_bytes)

	def generateSecretKey_sender(self, username):
		#Generate the 4 DH keys and generate secret
		# DH1 = Alice Idenity Key, Bob's Signed Pre_key
		dh1 = self.generateDH1_sender(username)


		#DH2 = Alice's Ephemeral Key, Bob's Idenity Key
		#Alice Generates a new Key for this exchange on the fly
		dh2 = alice.generateDH2_sender(username)


		#DH3 = Alice's Ephemeral Key, Bob's Signed Pre_key
		dh3 = alice.generateDH3_sender(username)


		#DH4 = Alice's Ephemeral Key, Bob's One Time Key
		dh4 = alice.generateDH4_sender(username)

		return self.generateSecretKey(dh1, dh2, dh3, dh4)


	def generateSecretKey(self, dh1, dh2, dh3, dh4):
		if self.idenity_private_key is X448PrivateKey:
			pre_hash_bytes = 57*b"\xFF"
			hash_obj = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=(64*b"\x00"), iterations=480000)
		else:
			pre_hash_bytes = 32*b"\xFF"
			hash_obj = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=(32*b"\x00"), iterations=480000)

		secret_key = hash_obj.derive(pre_hash_bytes + dh1 + dh2 + dh3 + dh4)
		return secret_key

	def AADAndEncryptMessage(self, secret_key, message, username):
		dst_idenity_key = self.signal_server.getUsersIdenityKey(username)

		# Dest Ident Key, Source Ident Key, dest username, source username, server info
		aad = {"src_idenity_key": base64.b64encode(self.idenity_private_key.public_key().public_bytes_raw()).decode('ascii') , 
		"src_username": self.username, "src_ephemeral_key": base64.b64encode(self.ephemeral_key.public_key().public_bytes_raw()).decode('ascii'),
		"dst_idenity_key": base64.b64encode(dst_idenity_key).decode('ascii'), "dst_username": username, "server_info": self.signal_server.info.decode('ascii')}

		#print(aad)
		aad_bytes = json.dumps(aad).encode('ascii')

		aesgcm = AESGCM(secret_key)
		nonce = os.urandom(12)
		cyphertext = aesgcm.encrypt(nonce, message,  aad_bytes)

		return {"aad":aad_bytes, "nonce":nonce, "cyphertext": cyphertext}

	def recieveMessage(self, message):
		aad, nonce, cyphertext = [json.loads(message["aad"]), message["nonce"],  message["cyphertext"]]

		src_username, src_idenity_key_bytes, src_ephemeral_key_bytes = [aad["src_username"], base64.b64decode(aad["src_idenity_key"]), base64.b64decode(aad["src_ephemeral_key"])]
		dst_idenity_key_bytes, dst_username, server_info = [base64.b64decode(aad["dst_idenity_key"]), aad["dst_username"], aad["server_info"]]


		src_idenity_key = X448PublicKey.from_public_bytes(src_idenity_key_bytes)
		src_ephemeral_key = X448PublicKey.from_public_bytes(src_ephemeral_key_bytes)

		#Generate DH1
		# DH1 = Src Idenity Key, Dst Signed Pre_key
		dh1 = self.private_pre_key.exchange(src_idenity_key)

		#Generate DH2
		#DH2 = Src Ephemeral Key, Dst Idenity Key
		dh2 = self.idenity_private_key.exchange(src_ephemeral_key)
		

		#Generate DH3
		#DH3 = Src Ephemeral Key, Dst Signed Pre_key
		dh3 = self.private_pre_key.exchange(src_ephemeral_key)
		

		#Generate DH4
		#DH4 = Src Ephemeral Key, Dst One Time Key
		message_one_time_priv_key = self.one_time_private_keys.pop(0)
		dh4 = message_one_time_priv_key.exchange(src_ephemeral_key)

		#Generate Secret Key
		secret_key = self.generateSecretKey(dh1, dh2, dh3, dh4)


		#Decrypt and Verify Cypher text
		aesgcm = AESGCM(secret_key)
		return aesgcm.decrypt(nonce, cyphertext, message["aad"])


if __name__ == '__main__':
	#Generate Server
	signal_server = Signal_Server()

	#Generate Users
	alice = Signal_User("alice", signal_server)
	bob = Signal_User("bob", signal_server)

	#Setup Users with the server
	alice.registerUser()
	alice.send_PreKeyToSignalServer()
	alice.send_OneTimeKeysToSignalServer()

	bob.registerUser()
	bob.send_PreKeyToSignalServer()
	bob.send_OneTimeKeysToSignalServer()


	#Setup Done lets send a message
	#Assume that Bob is offline Alice can only exchange messages with the server

	#Concat Secrets and feed through a KDF
	# Salt is either 57*b"\xFF" for X448 or 32*b"\xFF" for X25519
	secret_key = alice.generateSecretKey_sender("bob")

	#Alice Deletes her Ephemeral Private Key and DH ouputs
	encrypted_message = alice.AADAndEncryptMessage(secret_key, b"Test Message 12345", "bob")
	print(f"Message over the Wire: {encrypted_message}")


	####### Time for Bob to get message
	print(f"Message Recived: {bob.recieveMessage(encrypted_message)}")

