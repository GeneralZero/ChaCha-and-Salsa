# ChaCha-and-Salsa
A simple, commented and readable python implementations of 

**Asymetric Encryption:**
- [Elgamal](./Asymetric_Encryption/elgamal.py)
- [ECC (ECIES)](./Asymetric_Encryption/ecies.py)

**Hash Functions:**
- [Blake](./Hash_Functions/blake.py) ([Blake224](./Hash_Functions/blake.py#47), [Blake256](./Hash_Functions/blake.py#58), [Blake384](./Hash_Functions/blake.py#69), [Blake512](./Hash_Functions/blake.py#81))
- Blake2 ([Blake2b](./Hash_Functions/blake2.py#61), [Blake2s](./Hash_Functions/blake2.py#73))
- Blake3 [TODO]
- [Gimli](./Hash_Functions/gimli.py)
- [MD2](./Hash_Functions/md2.py)
- [MD4](./Hash_Functions/md4.py)
- [MD5](./Hash_Functions/md5.py)
- [RC4](./Hash_Functions/rc4.py)
- [RIPEMD-160](./Hash_Functions/ripemd-160.py)
- [SHA1](./Hash_Functions/sha1.py)
- SHA2 ([SHA224](./Hash_Functions/sha2.py#37), [SHA256](./Hash_Functions/sha2.py#34), [SHA384](./Hash_Functions/sha512.py#39), [SHA512](./Hash_Functions/sha512.py#36))
- [SHA3](./Hash_Functions/sha3.py) (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256, Keccak-224, Keccak-256, Keccak-384, Keccak-512)
- XOODOO [TODO] 
- Whirlpool [TODO]
- Rumba20 [TODO]
- [SipHash](./Hash_Functions/siphash.py)

**Key Derivation:**
- [Argon2](./Key_Derivation/argon2.py)
- [Bcrypt](./Key_Derivation/bcrypt.py)
- [Double Ratchet](./Key_Derivation/doubleRatchet.py)
- [HKDF](./Key_Derivation/hkdf.py)
- [PBKDF](./Key_Derivation/pbkdf2.py#34)
- [PBKDF2](./Key_Derivation/pbkdf2.py#50)
- [Scrypt](./Key_Derivation/scrypt.py)

**Key Exchange:**
- [DH](./Key_Exchange/dhkx.py)
- [ECDH](./Key_Exchange/ecdh.py)
- [x3DH](./Key_Exchange/x448_x3dh.py)
- [MQV](./Key_Exchange/mqv.py)
- [HMQV](./Key_Exchange/dhkx.py)

**Message Authentication Codes (MAC):**
- [CMAC](./Message_Authentication_Codes/cmac.py)
- [CBC Mac](./Message_Authentication_Codes/cbcmac.py)
- GMAC
- [HMAC](./Message_Authentication_Codes/hmac.py)
- [Poly1305](./Message_Authentication_Codes/poly1305.py)

**Signatures:**
- [DSA](./Signatures/dsa.py)
- [ECDSA](./Signatures/ecdsa.py)
- [EdDSA](./Signatures/eddsa.py)

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


While these should not be used in real world applications. Hopefully the simple implimenation and comments should let people under stand the flow of the program and how each of the implimenations work.

### Special Mentions
@oiidmnk for bringing the MD2 RFC Eratta to my attention and making the Pull Request. https://www.rfc-editor.org/errata/eid555



These Implimenations have been verified against some of the Test Vectors in the RFC's to make sure that the functions are correct.
