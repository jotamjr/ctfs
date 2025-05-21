#### Description

Can you make sense of this source code file and write a function that will decode the given encrypted file content?Find the encrypted file [here](https://challenge-files.picoctf.net/c_verbal_sleep/97b2fa78864cfef5beafa9815bc7b4941f2592d12e39287f7212359ce10f086c/enc_flag). It might be good to analyze [source file](https://challenge-files.picoctf.net/c_verbal_sleep/97b2fa78864cfef5beafa9815bc7b4941f2592d12e39287f7212359ce10f086c/block_chain.py) to get the flag.

# Solution

After reviewing the source code, it seems that the encrypt function is splitting the blockchain and inserting a token (inner_txt: our flag) and xoring that with a key.

```Python
def encrypt(plaintext, inner_txt, key):
    midpoint = len(plaintext) // 2

    first_part = plaintext[:midpoint]
    second_part = plaintext[midpoint:]
    modified_plaintext = first_part + inner_txt + second_part
    print("Modified Plaintext:", modified_plaintext)
    block_size = 16
    plaintext = pad(modified_plaintext, block_size)
    print("key str?:", key)
    key_hash = hashlib.sha256(key).digest()

    ciphertext = b''

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        cipher_block = xor_bytes(block, key_hash)
        ciphertext += cipher_block

    return ciphertext
```

It is very fortunate that we have the key, and we can just XOR the ciphertext (blockchain) with the key to get the cleartext, we just need to keep in mind that our flag would be surrounded by additional data related to the blockchain.

This is an implementation of a decrypting function.
```Python
def decrypt(ciphertext, key):
    block_size = 16
    key_hash = hashlib.sha256(key).digest()
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i : i + block_size]
        decrypted_block = xor_bytes(block, key_hash)
        print(decrypted_block)

```

```txt
picoCTF{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_[redacted]}
```
