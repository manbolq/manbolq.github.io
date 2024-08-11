---
title: Shes the Real one - CTFZone 2024
date: 2024-08-11 17:39 +0200
categories: [CTFs, CTFZone]
tags: [LLL, discrete-logarithm-problem, elliptic-curve]
math: true
---


In this challenge we are given a script written in sage and its output. Our goal is to solve the discrete logarithm problem (DLP) to recover the flag.


## Source code

```python
from functools import namedtuple

from secret import flag

assert len(flag) == 33

Point = namedtuple("Point", ["x", "y"])
R = RealField(prec=800)
inf = Point(R(0), R(1))


def lift_x(x):
    return Point(x, sqrt(x**3 - R(3) * x - R(2)))


def add(P, Q):
    if P.x == Q.x and P.y != Q.y:
        return inf
    elif P.y == Q.y:
        raise ValueError("Points have to differ!")
    elif P == inf:
        return Q
    elif Q == inf:
        return P

    lambda_ = (P.y - Q.y) / (P.x - Q.x)

    xr = lambda_**2 - P.x - Q.x
    yr = lambda_ * (Q.x - xr) - Q.y
    return Point(xr, yr)


def double(P):
    if P == inf:
        return P

    lambda_ = (R(3) * P.x**2 - R(3)) / (R(2) * P.y)

    xr = lambda_**2 - 2 * P.x
    yr = lambda_ * (P.x - xr) - P.y
    return Point(xr, yr)


def multiply_by_scalar(P, n: int):
    if n == 0 or P == inf:
        return inf
    elif n < 0:
        return multiply_by_scalar(Point(-P.x, P.y), -n)

    R0, R1 = P, double(P)
    for b in bin(n)[3:]:
        if b == "0":
            R0, R1 = double(R0), add(R0, R1)
        else:
            R0, R1 = add(R0, R1), double(R1)
    return R0


P = lift_x(R(5.0) + R.random_element())
s = int.from_bytes(flag, 'big')
Q = multiply_by_scalar(P, s)
with open("output.dump", 'wb') as f:
    f.write(dumps([P, Q]))
```

## Solution

Basically, we have two points on a EC: $P$ and $Q$ such that $sP = Q$, where $s$ is the flag. If we look at the function `lift_x`, we can see that the EC is given by:

$$y^2 = x^3 - 3x - 2$$

which happens to be a **singular** elliptic curve. This is because its discriminant equals 0:

$$\Delta = -16(4\cdot(-3)^3 + 27 \cdot (-2)^2) = 0$$

When working with elliptic curves for a cryptographic purpose, it is recommended not to use singular curves. This is because the DLP can be solved way easier in this case, losing the benefits from using ECs. 

This is done by using a bijective map from the points in the EC to another field. I modified [this script](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/singular_curve.py) to get the new values to solve the DLP. 

```python
sage: def convert(a2, a4, a6, Gx, Gy, Px, Py):
....:     x = R["x"].gen()
....:     f = x ** 3 + a2 * x ** 2 + a4 * x + a6
....:     roots = f.roots()
....: 
....:     # Singular point is a cusp.
....:     if len(roots) == 1:
....:         alpha = roots[0][0]
....:         u = (Gx - alpha) / Gy
....:         v = (Px - alpha) / Py
....:         return int(v / u)
....: 
....:     # Singular point is a node.
....:     if len(roots) == 2:
....:         if roots[0][1] == 2:
....:             alpha = roots[0][0]
....:             beta = roots[1][0]
....:         elif roots[1][1] == 2:
....:             alpha = roots[1][0]
....:             beta = roots[0][0]
....:         else:
....:             raise ValueError("Expected root with multiplicity 2.")
....: 
....:         t = (alpha - beta).sqrt()
....:         u = (Gy + t * (Gx - alpha)) / (Gy - t * (Gx - alpha))
....:         v = (Py + t * (Px - alpha)) / (Py - t * (Px - alpha))
....:         #print(f"{u= }")
....:         #print(f"{v = }")
....:         return u, v
....: 
sage: Point = namedtuple("Point", ["x", "y"])
....: R = RealField(prec=800)
....: inf = Point(R(0), R(1))
sage: P, Q = loads(open("output.dump", "rb").read())
sage: u, v = convert(0, -3, -2, P.x, P.y, Q.x, Q.y)
sage: u, v
(-0.0255408859554811738798041002165322931079942421023925984456108883926698635790160301023957268132468588844442587625949443627843717558842132804252110981655810107582508423839253193843193430437616212740859528940078530327120403783075376942554672383 + 0.999673778362026011045642698149942821234299157834807848290934968114452835874641498749615568668413323504604479874008017320163141381303262476934628184678853707459466272729242179963292727643184096804965784876572551930340983845195909603003611083*I,
 0.616102493558778718889121697959960828359310758354780522858233409838803408207266567874733084017785852701944769007794275457796861891302495500551050030643665165153695292761613720866701849968732429743187383424132585465710709515167367011982608081 - 0.787665993572564377470888374116309095706826262285644512113154045150748557206663706545942833730723205261253089081559068120018585286881818605664252444987049692223949452578002134090936176300260555751352465814226213709696901021366756511208028056*I)
```

So now we have two **complex numbers** $u, v$, such that $u^s = v$, and we still need to find $s$. 

```python
sage: u.abs()
1.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
sage: v.abs()
1.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

We see that $\|u\| = \|v\| = 1$, so there exist $\theta, \omega \in ]-\pi, \pi]$ such that

$$u = \cos(\theta) + i \sin(\theta), \qquad v = \cos(\omega) + i\sin(\omega)$$

Furthermore, using the De Moivre's formula, we get that:

$$v = u^s = (\cos(\theta) + i \sin(\theta))^s = \cos(s\theta) + i \sin(s\theta)$$

And as $\cos$ and $\sin$ are $2\pi$-periodic, $\exists k \in \mathbb{Z}$ such that:

$$s\theta = \omega + 2\pi k$$

Let $A$ be an upper bound for $s$. Obviously:

$$\begin{pmatrix}s & -k & -1\end{pmatrix}\begin{pmatrix}A\theta & 1 & 0 \\ 2\pi A & 0 & 0 \\ A\omega & 0 & A\end{pmatrix} = \begin{pmatrix}0 & s & -A\end{pmatrix}$$

and so, the vector $\begin{pmatrix}0 & s & -A\end{pmatrix}$ is a short vector generated by the lattice spanned by that matrix. We can use **LLL** to get that vector. Note that because none of $\theta, \pi, \omega$ are exact, we are not going to get a sound 0, and as we are multiplying everything by $A$ (which is big) we are not going to get anything close to 0 in the first position either (but its division by $A$ will be indeed small). 


```python
sage: def genM(A=2**1000):
....:     M = Matrix(QQ, [A*theta, 1, 0])
....:     M = M.stack(vector([R(A*2*pi), 0, 0]))
....:     M = M.stack(vector([A*w, 0, A]))
....:     return Matrix(QQ, M)
....: 
sage: M = genM()
sage: L = M.LLL()
sage: long_to_bytes(abs(int(L[-1][1])))
b'CTFZone{m4yb3_5h35_4_c0mpl3x_0n3}'
```


## Whole script

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes
from functools import namedtuple


def genM(A=2**1000):
    M = Matrix(QQ, [A*theta, 1, 0])
    M = M.stack(vector([R(A*2*pi), 0, 0]))
    M = M.stack(vector([A*w, 0, A]))
    return Matrix(QQ, M)


def convert(a2, a4, a6, Gx, Gy, Px, Py):
    x = R["x"].gen()
    f = x ** 3 + a2 * x ** 2 + a4 * x + a6
    roots = f.roots()

    # Singular point is a cusp.
    if len(roots) == 1:
        alpha = roots[0][0]
        u = (Gx - alpha) / Gy
        v = (Px - alpha) / Py
        return int(v / u)

    # Singular point is a node.
    if len(roots) == 2:
        if roots[0][1] == 2:
            alpha = roots[0][0]
            beta = roots[1][0]
        elif roots[1][1] == 2:
            alpha = roots[1][0]
            beta = roots[0][0]
        else:
            raise ValueError("Expected root with multiplicity 2.")

        t = (alpha - beta).sqrt()
        u = (Gy + t * (Gx - alpha)) / (Gy - t * (Gx - alpha))
        v = (Py + t * (Px - alpha)) / (Py - t * (Px - alpha))
        #print(f"{u= }")
        #print(f"{v = }")
        return u, v

    raise ValueError(f"Unexpected number of roots {len(roots)}.")


Point = namedtuple("Point", ["x", "y"])
R = RealField(prec=800)
P, Q = loads(open("output.dump", "rb").read())
u, v = convert(0, -3, -2, P.x, P.y, Q.x, Q.y)

theta = u.argument()
w = v.argument()

M = genM()
L = M.LLL()

print(long_to_bytes(abs(int(L[-1][1]))))
```
