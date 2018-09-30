# Fin's Obfuscated Cipher
## Examples:  
```python crypto.py --encrypt pubkey.txt > encrypted_message.txt```  
 To encrypt a message. Type your message. When done type a new line, then press the EOF key combo (Ctrl-D on Linux, Ctrl-Z on Windows), then type enter.  
  
```python crypto.py privkey.txt encrypted_message.txt```  
To decrypt the message.

```python crypto -h```  
To view help

```python keygen.py -h```  
To view help

```python keygen.py pubkey2.txt privkey2.txt```
To generate 2048 bit keys

```python keygen.py -K 4096 pubkey3.txt privkey3.txt```
To generate 4096 bit keys.
