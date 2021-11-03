from cryptopals_lib import *
from aes_lib import AES


def CBC_MAC(enc_obj, message, iv=None):
	#First Block is the IV
	cipher_block = iv
	if iv == None:
		cipher_block = b"\x00" * enc_obj.block_size

	blocks = to_blocks(message, enc_obj.block_size)

	for block in blocks:
		xor_block = fixedlen_xor(block, cipher_block)
		cipher_block = enc_obj.aes_block_encryption(xor_block)

	#Do regular CBC Encryption but the MAC is the last block
	return cipher_block

if __name__ == '__main__':
	key =       [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
	test = AES(key)

	out = CBC_MAC(test, add_PKCS7_pad(b"Message Data", test.block_size))
	print(out.hex())