# EncryptionUtil
BouncyCastle based Encryption/Decryption that may become handy for me


1. Create the public/private key pair using Open SSL

openssl genrsa -out private_key.pem 2048

2. Extract the public key

openssl rsa -pubout -in private_key.pem -out public_key.pem

3. Viewing the private key

openssl rsa -text -in private_key.pem
