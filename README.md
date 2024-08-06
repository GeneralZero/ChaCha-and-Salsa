# ChaCha-and-Salsa
A simple, commented and readable python implementations of 

**Asymetric Encryption:**
- [Elgamal](./Asymetric_Encryption/elgamal.py)
- [ECC (ECIES)](./Asymetric_Encryption/ecies.py)

**Symetric Encryption:**
- [AES](./aes_lib.py)
- [Blowfish](./Symetric_Encryption/blowfish.py)
- [ChaCha](./Symetric_Encryption/chacha.py#L276)
- [Salsa](./Symetric_Encryption/chacha.py#L235)
- [XChaCha](./Symetric_Encryption/chacha.py#L262)
- [XSalsa](./Symetric_Encryption/chacha.py#L220)
- [DES](./Symetric_Encryption/des.py)
- [3DES](./Symetric_Encryption/des.py#158)
- [TEA](./Symetric_Encryption/tea.py)
- [XTEA](./Symetric_Encryption/tea.py#35)

**Hash Functions:**
- [Blake](./Hash_Functions/blake.py) ([Blake224](./Hash_Functions/blake.py#47), [Blake256](./Hash_Functions/blake.py#58), [Blake384](./Hash_Functions/blake.py#69), [Blake512](./Hash_Functions/blake.py#81))
- Blake2 (Blake2b, Blake2s)
- Blake3 [TODO]
- Gimli
- MD2
- MD4
- MD5
- RC4
- RIPEMD-160
- SHA1
- SHA2 (SHA224, SHA256, SHA384, SHA512)
- SHA3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256, Keccak-224, Keccak-256, Keccak-384, Keccak-512)
- XOODOO [TODO] 
- Whirlpool [TODO]
- Rumba20 [TODO]
- SipHash

**Key Derivation:**
- Argon2 
- Bcrypt
- Double Ratchet
- HKDF
- PBKDF
- PBKDF2
- Scrypt 

**Message Authentication Codes (MAC):**
- CMAC
- CBC Mac
- GMAC
- HMAC
- Poly1305

**Signatures:**
- DSA
- ECDSA
- EdDSA

**Key Exchange:**
- DH
- ECDH
- x3DH
- MQV/HMQV


While these should not be used in real world applications. Hopefully the simple implimenation and comments should let people under stand the flow of the program and how each of the implimenations work.

### Special Mentions
@oiidmnk for bringing the MD2 RFC Eratta to my attention and making the Pull Request. https://www.rfc-editor.org/errata/eid555



These Implimenations have been verified against some of the Test Vectors in the RFC's to make sure that the functions are correct.
