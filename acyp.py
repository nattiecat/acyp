#!/bin/usr/python

# a simple affine cypher program. A plaintext character p is encrypted
# by an invertible function f on Z_mod_256 with f(p) = a*p + b (mod 256),
# where a and b are the 'keys' to the affine cypher f.

import sys

_a = 51     # cypher key _a in q = _a*p + _b (mod 255)
_b = 201     # cypher key _b in q = _a*p + _b (mod 255)
_a_inv = 251 # cypher key _a_inv in p = (_a_inv)*(q - _b) (mod 255)

# sets the cypher key 'a' to the given integer value
def set_a(i):
    if not isinstance(i,int):
        raise TypeError('Argument must be an int')
    if i % 2 == 0:
        raise ValueError('Argument must be an odd integer')
    global _a
    _a = i
    global _a_inv
    _a_inv = __brute_force_mult_inv(_a)

def set_b(j):
    if not isinstance(j,int):
        raise TypeError('Argument must be an int')
    global _b
    _b = j % 256

# brute force calculation of the multiplicative inverse of _a
# in Z_mod_256 until I bother programming a more efficient algorithm
# returns the multiplicative inverse of the given _a in Z_mod_256, if
# it exists; otherwise returns -1 to indicate _a has no inverse
def __brute_force_mult_inv(_a):
    for x in range(0,255):
        if ((x * _a) % 256 == 1):
            return x
    return -1

# encrypts the given cleartext string using an affine cypher 
# with keys _a and _b and returns the encrypted string. Assumes
# the given string consists only of ASCII characters
def encrypt(s):
    if (_a == -1):
        raise ValueError('Invalid encryption key; call set_a() '\
                         'with valid parameter')
    t = ''
    for p in s:
        q = (_a * ord(p) + _b) % 256
        t += chr(q)
    return t

# decrypts the given cyphertext string using an affine cypher
# with keys _a_inv and _b, where _a_inv is the multiplicative
# inverse of _a in the finite number system Z_mod_256. Returns
# the decrypted string. Assumes the encrypted string consists
# only of ASCII characters. This function will only properly
# decrypt cyphertext that was encrypted with matching values
# of _a and _b
def decrypt(t):
    s = ''
    for q in t:
        p = (_a_inv * (ord(q) - _b)) % 256
        s += chr(p)
    return s

