---
title: The Last Dance - HackTheBox CTF
date: 2023-11-09 11:47:00 +0100
categories: [CTFs, HackTheBox]
tags: [chacha20, stream-cipher, python]
img_path: /assets/images/BabyTimeCapsule
math: true
---


In this HTB challenge, we are given some ciphertexts and the source code used to generate them. It is usign ChaCha20, which is a stream cipher algorithm. The vulnerability of this script comes when it encrypts two differents messages using the same stream, and we know one of the messages.

## Source code
This is the intereseting part of the source code:

```python
def encryptMessage(message, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=iv)
    ciphertext = cipher.encrypt(message)
    return ciphertext


def writeData(data):
    with open("out.txt", "w") as f:
        f.write(data)


if __name__ == "__main__":
    message = b"Our counter agencies have intercepted your messages and a lot "
    message += b"of your agent's identities have been exposed. In a matter of "
    message += b"days all of them will be captured"

    key, iv = os.urandom(32), os.urandom(12)

    encrypted_message = encryptMessage(message, key, iv)
    encrypted_flag = encryptMessage(FLAG, key, iv)

    data = iv.hex() + "\n" + encrypted_message.hex() + "\n" + encrypted_flag.hex()
    writeData(data)
```

## How the attack works

This attack is quite simple. When we have a stream cipher algorithm, it generates a bytes stream, which is used to make an XOR operation to the plaintext. Let's call the stream $$s$$. Basically, we have the following:

$$
ct_1 = pt_1 \oplus s
$$

$$
ct_2 = pt_2 \oplus s
$$

So what it we xor both cipertexts?

$$
ct_1 \oplus ct_2 = pt_1 \oplus s \oplus pt_2 \oplus s = pt_1 \oplus pt_2
$$

And if we know $pt_1$, it is as simple as xor both sides of the equation with $pt_1$:

$$
ct_1 \oplus ct_2 \oplus pt_1 = pt_1 \oplus pt_2 \oplus pt_1 = pt_2 
$$

And we get back the second plain text!

## Script to get the flag

I have done this procedure using python. This is the script I used:

```python
#!/usr/bin/python3

e_message = bytes.fromhex("7aa34395a258f5893e3db1822139b8c1f04cfab9d757b9b9cca57e1df33d093f07c7f06e06bb6293676f9060a838ea138b6bc9f20b08afeb73120506e2ce7b9b9dcd9e4a421584cfaba2481132dfbdf4216e98e3facec9ba199ca3a97641e9ca9782868d0222a1d7c0d3119b867edaf2e72e2a6f7d344df39a14edc39cb6f960944ddac2aaef324827c36cba67dcb76b22119b43881a3f1262752990")
e_flag = bytes.fromhex("7d8273ceb459e4d4386df4e32e1aecc1aa7aaafda50cb982f6c62623cf6b29693d86b15457aa76ac7e2eef6cf814ae3a8d39c7")
message = b"Our counter agencies have intercepted your messages and a lot of your agent's identities have been exposed. In a matter of days all of them will be captured"


xored = b""
for i in range(len(e_flag)):
    xored += bytes([e_flag[i] ^ e_message[i]])

pt = b""
for i in range(len(xored)):
    pt += bytes([xored[i] ^ message[i]])

print(pt)
```

Easy peasy!
