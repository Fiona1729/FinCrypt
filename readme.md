# FinCrypt
## About
FinCrypt is a hybrid cryptosystem with signatures. FinCrypt utilizes 4096 bit RSA, AES-256, and SHA-256 for message 
encryption and authentication.

## Warning
FinCrypt is not designed to be a hardened cryptosystem! FinCrypt is probably vulnerable to a large number of 
side-channel attacks, timing attacks, and other exotic cryptanalysis. FinCrypt simply provides a simple showcase of a 
hybrid cryptosystem with signatures, and attempts to make all the workings of the cryptographic components easily 
dissectable. Additionally, FinCrypt does not provide any methods of PKI other than hash validation and a simple SSH-style randomart visualization.

## Getting Started
If you already understand public key cryptography and command line usage, you can skip this section.

NOTE: This guide assumes you have Python 3 in your PATH environment variable and it is set as the 
default program for `.py` files. To test this, go into a command prompt or terminal and type `python`. 
If this gives you an error, you will have to install python in your path, as explained 
[here](https://www.pythoncentral.io/add-python-to-path-python-is-not-recognized-as-an-internal-or-external-command/).
  
  
First, generate a keypair by typing `python keygen.py` in your terminal. Follow the prompts on screen. Name your public 
key file something descriptive, preferably your name or whatever username you will be conversing under.
E.G. `fin_blackett.asc`

Then, distribute the public key to whoever you want to send messages to. It is very important
that you never share the private key.

Rename the private key `private.asc` and drop it into the private_key directory. This will be
used to decrypt and sign your messages, so **DON'T LOSE IT**.

Have your friend put your public key into their public_keys directory. Try and remember the filename. If it isn't a good 
name, you can rename it to something you'll find more memorable or descriptive. Likewise, put your friend's 
key into your public_keys directory.

Once your correspondents have your public key, and you have theirs, you can start encrypting 
and decrypting messages!

To start, make a text file. Name it something like `message.txt`. Put whatever text you'd like in there. Then, go 
into your command line, and type `python fincrypt.py e {friend's key file name} message.txt > message.asc`. This will 
encrypt the message and save it to a file called `message.asc`. Send this file to your friend, and have them run the 
command `python fincrypt.py d {your key file name} message.asc`. They will see the message you sent.

## CLI Usage
```fincrypt.py e {recipient's public key name} {file to encrypt} > {output file}```  
 To encrypt a file.
 
```fincrypt.py d {sender's public key name} {file to decrypt} > {output file}```  
To decrypt a file.

```fincrypt.py eb {recipient's public key name} {binary file to encrypt} > {output file}```  
To encrypt a message using binary encoding. This means that output will be unable to be sent over purely text channels,
however it will provide space savings.

```fincrypt.py db {sender's public key name} {binary file to decrypt} > {output file}```  
Decrypt the binary encoded message.

```fincrypt.py -h``` 
To view general help.

```fincrypt.py [e|d|eb|db] -h```  
To view help for a specific mode.

```fincrypt.py -N```
To enumerate a list of all known public keys. Use this if you forget the filename of your friend's public key, or to
verify a friend's key validity.

Do this by looking at what the key's hash is, and what your friend's key's hash should be. If they are different, this
means the key you have is NOT your friend's public key. 

You can also do this by looking at the randomart which is generated based on the hash. This is faster and usually easier, but less secure.

```keygen.py```  
To generate a new keypair.