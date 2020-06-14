#!/usr/bin/env python2.7
# vim: set fileencoding=utf-8 :

# a simple affine cypher program for encrypting and decrypting ASCII text.
# A plaintext character 'p' is encrypted  by an invertible function 'e' on
# Z_mod_256 with e(p) = a*p + b (mod 256), where 'a' and 'b' are elements
# of Z_mod_256 that act as the 'keys' to the cypher 'e'. 'a' must be rela-
# tively prime to 256 (so that any odd integer (mod 256) will do) in order 
# for 'e' to be invertible, in which case the inverse function 'd' acts to
# decrypt a cyphertext character 'q' with d(q) = ã*(q - b), where 'ã' is 
# the multiplicative inverse of 'a' in Z_mod_256. 'b' is any old integer
# (mod 256). Good for 'b'.  

import sys

_a = 51     # cypher key 'a' in e(p) = a*p + b (mod 255)
_b = 201     # cypher key 'b' in e(p) = a*p + b (mod 255)
_a_inv = 251 # cypher key 'ã' in d(q) = ã*(q-b) (mod 255)

# sets the cypher key 'a' to the given odd integer value
def set_a(i):
    if not isinstance(i,int):
        raise TypeError('Argument must be an int')
    if i % 2 == 0:
        raise ValueError('Argument must be an odd integer')
    global _a
    _a = i
    global _a_inv
    _a_inv = __brute_force_mult_inv(_a)

# sets the cypher key 'b' to the given integer value
def set_b(j):
    if not isinstance(j,int):
        raise TypeError('Argument must be an int')
    global _b
    _b = j % 256

# brute force calculation of the multiplicative inverse of _a
# in Z_mod_256 until I bother programming a more efficient algorithm
# (not that I really need to for this project, but it will be fun to
# try to implement the Euclidean Algorithm / Bezout's Theorm for cal-
# culating multiplicative inverses in finite rings).
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

# a main function to do some practice with running acyp from
# the command line.  This version will read text from a file
# whose name is given as sys.argv[1]; encrypt the text and
# write it to a file of the same name with the suffix '.enc';
# then read the encrypted file, decrypt it, and write the de-
# crypted text to a file of the same name with the suffix '.dec'
# If all goes well, the original file and the '.dec' file should
# have the exact same contents! 
def main():
    if len(sys.argv) < 2:
        print 'this is some usage info about how to invoke acyp'
        sys.exit(1)
    # step one: encryption
    fname = sys.argv[1]
    fin = open(fname)
    fout = open(fname + '.enc', 'w')
    for line in fin:
        s = encrypt(line)
        fout.write(s)
    fout.close()
    fin.close()
    # step two: decryption
    fin = open(fname + '.enc')
    fout = open(fname + '.dec', 'w')
    for line in fin:
        s = decrypt(line)
        fout.write(s)
    fout.close()
    fin.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
