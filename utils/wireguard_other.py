# import codecs
# from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
# from cryptography.hazmat.primitives import serialization
 
# # generate private key
# private_key = X25519PrivateKey.generate()
# bytes_ = private_key.private_bytes(  
#     encoding=serialization.Encoding.Raw,  
#     format=serialization.PrivateFormat.Raw,
#     encryption_algorithm=serialization.NoEncryption()
# )
# print(codecs.encode(bytes_, 'base64').decode('utf8').strip())
 
# # derive public key
# pubkey = private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
# print(codecs.encode(pubkey, 'base64').decode('utf8').strip())
