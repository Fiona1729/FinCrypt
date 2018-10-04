# FinCrypt
## About
FinCrypt is a hybrid cryptosystem with signatures. FinCrypt utilizes 4096 bit RSA, AES-256, and SHA-256 for message encryption and authentication.

## Warning
FinCrypt is not designed to be a hardened cryptosystem! FinCrypt doesn't use secure random numbers for key generation, has very little error catching on decryption, and is probably vulnerable to a large number of side-channel, timing, and other exotic attacks.   
FinCrypt simply provides a simple showcase of a hybrid cryptosystem with signatures, and attempts to make all the workings of the cryptographic components easily dissectable.  
Additionally, FinCrypt does not provide any methods of PKI other than hash validation and a simple SSH-style randomart visualization.

## Examples:  
```crypto.py e {public key name} {file to encrypt} > encrypted_message.txt```  
 To encrypt a message.
  
```crypto.py d {public key name} encrypted_message.txt```  
To decrypt the message.

```crypto.py eb {public key name} {file to encrypt} > encrypted_message.bin```  
To encrypt a message using binary encoding. This means that output is unable to be sent over purely text channels, however it will provide space savings.

```crypto.py db {public key name} encrypted_message.bin```
Decrypt the binary encoded message.

```crypto.py [e|d] -h```  
To view help.

```crypto.py -N```
To enumerate a list of all known public keys.

```keygen.py```  
To generate a keypair.
