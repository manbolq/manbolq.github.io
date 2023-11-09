---
title: Baby Time Capsule - HackTheBox CTF
date: 2023-11-09 10:58:00 +0100
categories: [CTFs, HackTheBox]
tags: [rsa, python, chinese-remainder-theorem]
img_path: /assets/images/BabyTimeCapsule
math: true
---


In this HTB challenge, we are given the source code of a encrypting algorithm that is using RSA. We are also given a remote instance serving this script, so that we can retrieve the flag. The vulnerability of this program comes when it encrypts the same text (the flag) using different primes in the RSA algorithm. We'll be able to use the Chinese Remainder Theorem in order to get the plaintext. Let's get into it.


## Source code
This is the intereseting part of the source code:

```python
def __init__(self, msg):
    self.msg = msg
    self.bit_size = 1024
    self.e = 5

def _get_new_pubkey(self):
    while True:
        p = getPrime(self.bit_size // 2)
        q = getPrime(self.bit_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        try:
            pow(self.e, -1, phi)
            break
        except ValueError:
            pass

    return n, self.e

def get_new_time_capsule(self):
    n, e = self._get_new_pubkey()
    m = bytes_to_long(self.msg)
    m = pow(m, e, n)

    return {"time_capsule": f"{m:X}", "pubkey": [f"{n:X}", f"{e:X}"]}
```

Besides, when we connect to the instance, we are asked to type 'Y' or 'N', asking whether we want to generate a cipher text or not. If we say 'Y', then this code will be executed and will print the result:

![example execution](example.png)

## Chinese Remainder Theorem

Let's say we run the program three times, and we get three cyphertexts: $$ct_1, ct_2, ct_3$$ and three "n's": $$n_1, n_2, n_3$$. Taking into account that $$e=5$$, we have the following set of congruences:

$$
m^5 \equiv ct_1 ~ (mod \quad n_1)
$$

$$
m^5 \equiv ct_2 ~ (mod \quad n_2)
$$

$$
m^5 \equiv ct_3 ~ (mod \quad n_3)
$$

So we can apply the Chinese Remainder Theorem in order to get the value of $$m^5$$. We'll take the 5-th root, and that will be the plaintext!

## Solution

This is a little python script I wrote to connect to the instance, get the required values and solve the set of congruences:

```python
#!/usr/bin/python3

from pwn import *
from Crypto.Util.number import long_to_bytes
import json
from sympy.ntheory.modular import crt
from sympy.simplify.simplify import nthroot


ip = "206.189.24.162"
port = 32270

r = remote(ip, port)
ct = []
n = []
for i in range(3):
    r.sendlineafter(b"(Y/n) ", b"Y")
    data = r.recvuntil(b"}")
    json_data = json.loads(data)
    ct.append(int(json_data["time_capsule"], 16))
    n.append(int(json_data["pubkey"][0], 16))


solution = crt(n, ct)[0]
m = nthroot(solution, 5)

print(long_to_bytes(m))
```

And when we execute this script, we'll get the flag :)
