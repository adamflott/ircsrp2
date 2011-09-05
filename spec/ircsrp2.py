#!/usr/bin/env python
##
## ircsrp2.py - IRCSRP2 reference implementation.
##
## Copyright (c) 2009, Bjorn Edstrom <be@bjrn.se>
## 
## Permission to use, copy, modify, and distribute this software for any
## purpose with or without fee is hereby granted, provided that the above
## copyright notice and this permission notice appear in all copies.
## 
## THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
## WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
## MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
## ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
## WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
## ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
## OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
##

"""
s, v = ircsrp_generate("alice", "passw")
dave = IRCSRPCtx(True)
dave.users.db["alice"] = (s, v)

dave.username = "dave"
dave.sessionkey = urandom(32)
dave.mackey = urandom(32)
dave.cipher = AESCBC(dave.sessionkey)

alice = IRCSRPCtx()
alice.username = "alice"
alice.password = "passw"

>>> ircsrp_exchange(alice)
'+srpa0 alice'
>>> ircsrp_exchange(dave, _, "alicenick")
'+srpa1 VhUINb7/yJBOOWo9Pi7UFQENBhtml/4BgVdHp1NBnOeypN5z2UMzI0
DHUJZL21G1zjK1jV6S2kIJGCvIiTP0cjs0LiCMzo9OHz9ohUJpeDVNKf9a3/r1
4AkI7PhXzQlHUXzr1HSFFWBI8NxIaMBFRMtaXuwHlyUoOY6AscPUScVKXYw1ig
U8w/Q6C2zjdZm9GpPra4LiDjc/uQ30WMQrx5QDcYSnMqEOMBxbmUSkBpB+kvqF
TL0kMfMhMzw8U1fzr9Gh1BPZ/ym9vW4CFd+gD5rOjQaM/5+p1TWYwdnz6sbL5S
eOQZyERhwEb0QjzVWRvopKI0SmBJc5UynK9V3PIAOVvQjqpZEb6qpW0UREPwDJ
I/EdeRVpO1ym3NjD6h1P'
>>> ircsrp_exchange(alice, _)
'+srpa2 3uQ8wkFcAhLEImMTV9b8BqpBKwfuo3GALV3Y37JfxoUvoU763Q+jd+
D89tTWipXJPvZk2wruYcqjf9UICOedZoq1Hw7hfKSB1xE6fMuVFCKLBdD1n8vb
9q0CaTEwAC5WFNNjIHhBq8bxpTkAlblYeAZZJSHX5/jKlcWZDK2zLXGFNFbK7/
CTN6Eguq6Oau3fJm5FInG7khQifM7s1Q8mpbHHoC4ua0PqE13Pr0hqdPEBdjuK
CvbMv0Yjo5Aw3g5RLjZDn6GuHJ+JULt0m2qwH56G8S3RRf7sFpNTSisRNIMf0T
llaiEuBrFmcU54Hmi9mrJkEqvdUEO5L8AxX8fmd9bIokoFyXrMKz8L69cP6l3c
eNq8nWXpFNZeKv6sZdCW'
>>> ircsrp_exchange(dave, _, "alicenick")
'+srpa3 kfpPk77f177721H5uxz+U5YdwKEG9xB0dzOzj6RKZ1lv0Kkjci/HAY
YC1MVsRAQVVe9PJ8pvcF6PJKWvLV+PrADoGtjkPL1cHGFqjjHAA6+AYqpjC1CG
r4mas9rpiu+7fCJviddRPLwPpdIoFB325sDiEp5IvCnCVdJVZlZydoo='
>>> ircsrp_exchange(alice, _)
*** Session key is: "\x93\xa8T\xfc'\x9fx{\xea\x13O\xd2D\xad\xf8
\xae\x19,[\xbaH]\xa9\xf2\x1c\xd1\x03N\x07\xa5\xbb\x9f"
*** MAC key is: '\x19\xcaF\x93\xa9cT\xc0\x89Fkq\xa6\xd3\xca\xb1U6
\xfb\x05A<\x04\x06\xcdj\xba\x1a\xcb#\xca\x9e'
True

>>> dave.sessionkey
"\x93\xa8T\xfc'\x9fx{\xea\x13O\xd2D\xad\xf8\xae\x19,[\xbaH]\xa9
\xf2\x1c\xd1\x03N\x07\xa5\xbb\x9f"
>>> dave.mackey
'\x19\xcaF\x93\xa9cT\xc0\x89Fkq\xa6\xd3\xca\xb1U6\xfb\x05A<\x04
\x06\xcdj\xba\x1a\xcb#\xca\x9e'

>>> ircsrp_pack(alice, "Hello everyone!")
'*GBvBOrayALS4vaifsFeuIRh6qn+EBhKiBCPzsembi0z5I0dMVUqr/fHTnlU/1q
IqK6fTm7ekNe1wsXNqNFpDeA=='
>>> ircsrp_unpack(dave, _)
*** Sent by username: alice
*** Sent at time: Thu Feb 12 22:37:35 2009
'Hello everyone!'

"""

__author__ = "Bjorn Edstrom <be@bjrn.se>"
__date__ = "2009-02-13"
__version__ = "0.2.0"

import base64
import hashlib
import hmac
from math import log
try:
    import Crypto.Cipher.Blowfish
    import Crypto.Cipher.AES
except ImportError:
    print "This module requires PyCrypto / The Python Cryptographic Toolkit."
    print "Get it from http://www.dlitz.net/software/pycrypto/."
    raise
from os import urandom
import struct
import time

##
## Preliminaries.
##

class MalformedError(Exception):
    pass


def sha256(s):
    """sha256"""
    return hashlib.sha256(s).digest()


def hmac_sha256_128(key, s):
    return hmac.new(key, s, digestmod=hashlib.sha256).digest()[0:16]


def int2bytes(n):
    """Integer to variable length big endian."""
    if n == 0:
        return '\x00'
    b = ''
    while n:
        b = chr(n % 256) + b
        n /= 256
    return b


def bytes2int(b):
    """Variable length big endian to integer."""
    n = 0
    for p in b:
        n *= 256
        n += ord(p)
    return n


# FIXME! Only usable for really small a with b near 16^x.
def randint(a, b):
    """Random integer in [a,b]."""
    bits = int(log(b, 2) + 1) / 8
    candidate = 0
    while True:
        candidate = bytes2int(urandom(bits))
        if a <= candidate <= b:
            break
    assert a <= candidate <= b
    return candidate


def padto(msg, length):
    """Pads 'msg' with zeroes until it's length is divisible by 'length'.
    If the length of msg is already a multiple of 'length', does nothing."""
    L = len(msg)
    if L % length:
        msg += '\x00' * (length - L % length)
    assert len(msg) % length == 0
    return msg


def xorstring(a, b, blocksize): # Slow.
    """xor string a and b, both of length blocksize."""
    xored = ''
    for i in xrange(blocksize):
        xored += chr(ord(a[i]) ^ ord(b[i]))  
    return xored


def cbc_encrypt(func, data, blocksize):
    """The CBC mode. The randomy generated IV is prefixed to the ciphertext.
    'func' is a function that encrypts data in ECB mode. 'data' is the
    plaintext. 'blocksize' is the block size of the cipher."""
    assert len(data) % blocksize == 0
    
    IV = urandom(blocksize)
    assert len(IV) == blocksize
    
    ciphertext = IV
    for block_index in xrange(len(data) / blocksize):
        xored = xorstring(data, IV, blocksize)
        enc = func(xored)
        
        ciphertext += enc
        IV = enc
        data = data[blocksize:]

    assert len(ciphertext) % blocksize == 0
    return ciphertext


def cbc_decrypt(func, data, blocksize):
    """See cbc_encrypt."""
    assert len(data) % blocksize == 0
    
    IV = data[0:blocksize]
    data = data[blocksize:]

    plaintext = ''
    for block_index in xrange(len(data) / blocksize):
        temp = func(data[0:blocksize])
        temp2 = xorstring(temp, IV, blocksize)
        plaintext += temp2
        IV = data[0:blocksize]
        data = data[blocksize:]
    
    assert len(plaintext) % blocksize == 0
    return plaintext


class AESCBC:
    
    def __init__(self, key):
        self.aes = Crypto.Cipher.AES.new(key)

    def decrypt(self, data):
        return cbc_decrypt(self.aes.decrypt, data, 16)
    
    def encrypt(self, data):
        return cbc_encrypt(self.aes.encrypt, data, 16)

##
## IRCSRP version 2
##

modp14 = """
      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""
g = 2
N = int(modp14.replace(' ', '').replace('\n', ''), 16)
H = sha256

class IRCSRPExchange:
    def __init__(self):
        self.status = 0
        self.I = 0
        self.x = 0
        self.a = 0
        self.A = 0
        self.b = 0
        self.B = 0
        self.S = 0
        self.u = 0
        self.K1 = 0
        self.K2 = 0
        self.M1 = 0
        self.M2 = 0

class IRCSRPUsers:
    def __init__(self):
        # Store info about friends here, such as
        # self.db["alice"] = alice_s, alice_v
        self.db = {}

        # Temporary storage for exchange. The dict key is derived from the
        # IRC message, not the username.
        self.others = {}
        
    def get_details(self, username):
        s, v = self.db[username]
        return s, v


class IRCSRPCtx:
    """Everyone has one of these."""
    def __init__(self, dave=False):
        self.cipher = None
        self.status = 0
        self.username = ''
        self.password = ''
        self.sessionkey = ''
        self.mackey = ''
        self.ex = IRCSRPExchange()
        self.isdave = dave
        if dave:
            self.users = IRCSRPUsers()
            
    def set_key(self, key):
        assert len(key) == 32 + 32
        davemsg = ''
        if self.isdave:
            davemsg = ircsrp_pack(self, '\xffKEY' + key)
        self.sessionkey = key[0:32]
        self.mackey = key[32:]
        self.cipher = AESCBC(self.sessionkey)
        if self.isdave:
            return davemsg
        return None


def ircsrp_generate(username, password):
    """Alice runs this and gives the result to Dave."""
    s = urandom(32)
    x = bytes2int(H(s + username + password))
    v = pow(g, x, N)
    return s, v


def ircsrp_pack(ctx, msg):
    """Encrypt message for channel."""
    times = struct.pack(">L", int(time.time()))
    infos = chr(len(ctx.username)) + ctx.username + times
    ctext = ctx.cipher.encrypt(padto("M" + infos + msg, 16))
    cmac = hmac_sha256_128(ctx.mackey, ctext)
    return '*' + base64.b64encode(cmac + ctext)


def ircsrp_unpack(ctx, msg):
    """Decrypt message for channel."""
    if not msg.startswith('*'):
        raise ValueError

    try:
        coded = msg[1:]
        raw = base64.b64decode(coded)
    except TypeError:
        raise MalformedError
    if not raw:
        raise MalformedError

    cmac, ctext = raw[:16], raw[16:]

    if cmac != hmac_sha256_128(ctx.mackey, ctext):
        print "Wrong MAC!"
        raise ValueError

    try:
        padded = ctx.cipher.decrypt(ctext)
    except ValueError:
        raise MalformedError
    if not padded:
        raise MalformedError

    plain = padded.strip("\x00")

    if not plain[0] == 'M':
        raise ValueError

    usernamelen = ord(plain[1])
    username = plain[2:2+usernamelen]
    timestampstr = plain[2+usernamelen:4+2+usernamelen]
    timestamp = struct.unpack(">L", timestampstr)[0]

    print "*** Sent by username:", username
    print "*** Sent at time:", time.ctime(timestamp)

    plain = plain[4+2+usernamelen:]

    # New key?
    if plain.startswith('\xffKEY'):
        new = plain[4:]
        if not len(new) == 32 + 32:
            raise MalformedError
        ctx.sessionkey = new[:32]
        ctx.mackey = new[32:]
        ctx.cipher = AESCBC(ctx.sessionkey)
        print "*** Session key changed to:", repr(ctx.sessionkey)
        print "*** MAC key changed to:", repr(ctx.mackey)
        return None    
        
    return plain


def ircsrp_exchange(ctx, msg=None, sender=None):
    """The key exchange, for NOTICE handler. Parameters are:
    
    :<sender>!user@host.com NOTICE :<msg>\r\n
    """
    b64 = lambda s: base64.b64encode(s)
    b64i = lambda i: b64(int2bytes(i))
    unb64 = lambda s: base64.b64decode(s)
    unb64i = lambda s: bytes2int(unb64(s))

    cmd, arg = '', ''
    if msg:
        cmd, arg = msg.split(' ', 1)
        if not cmd.startswith('+srp'):
            raise ValueError
        cmd = cmd[5:].strip(' ')
    
    # Alice initiates the exchange.
    if msg == None and sender == None and ctx.ex.status == 0:
        
        ctx.ex.status = 1
        
        return "+srpa0 " + ctx.username

    # Dave
    if cmd == '0':
        
        ex = ctx.users.others[sender] = IRCSRPExchange()

        I = ex.I = arg
        s, v = ex.s, ex.v = ctx.users.get_details(I)
        b = ex.b = randint(2, N-1)
        B = ex.B = (3*v + pow(g, b, N)) % N

        return "+srpa1 " + b64(s + int2bytes(B))

    # Alice
    if cmd == '1' and ctx.ex.status == 1:

        args = unb64(arg)
        s = ctx.ex.s = args[:32]
        B = ctx.ex.B = bytes2int(args[32:])
        if B % N == 0:
            raise ValueError
        
        a = ctx.ex.a = randint(2, N-1)
        A = ctx.ex.A = pow(g, a, N)
        x = ctx.ex.x = bytes2int(H(s + ctx.username + ctx.password))
        
        u = ctx.ex.u = bytes2int(H(int2bytes(A) + int2bytes(B)))
        S = ctx.ex.S = pow(B - 3*pow(g, x, N), (a + u*x) % N, N)
        K1 = ctx.ex.K1 = sha256(int2bytes(S) + "enc")
        K2 = ctx.ex.K2 = sha256(int2bytes(S) + "auth")
        M1 = ctx.ex.M1 = H(int2bytes(A) + int2bytes(B) + int2bytes(S))

        ctx.ex.status = 2
        
        return "+srpa2 " + b64(M1 + int2bytes(A))

    # Dave
    if cmd == '2':
        
        if not sender in ctx.users.others:
            raise ValueError
        ex = ctx.users.others[sender]

        args = unb64(arg)
        M1 = args[:32]
        A = bytes2int(args[32:])
        if A % N == 0:
            raise ValueError

        u = bytes2int(H(int2bytes(A) + int2bytes(ex.B)))
        S = pow(A * pow(ex.v, u, N), ex.b, N)
        K1 = ctx.ex.K1 = sha256(int2bytes(S) + "enc")
        K2 = ctx.ex.K2 = sha256(int2bytes(S) + "auth")
        M2 = H(int2bytes(A) + M1 + int2bytes(S))

        M1ver = H(int2bytes(A) + int2bytes(ex.B) + int2bytes(S))
        if M1 != M1ver:
            raise ValueError

        aes = AESCBC(K1)

        del ctx.users.others[sender]

        csession = aes.encrypt(ctx.sessionkey + ctx.mackey + M2)
        cmac = hmac_sha256_128(K2, csession)
        return "+srpa3 " + b64(cmac + csession)

    # Alice
    if cmd == '3' and ctx.ex.status == 2:

        cipher = unb64(arg)
        aes = AESCBC(ctx.ex.K1)
        cmac = cipher[0:16]
        if hmac_sha256_128(ctx.ex.K2, cipher[16:]) != cmac:
            print "Incorrect MAC!"
            raise ValueError
        
        plain = aes.decrypt(cipher[16:])

        sessionkey = plain[:32]
        mackey = plain[32:64]
        M2 = plain[64:96]

        M2ver = H(int2bytes(ctx.ex.A) + ctx.ex.M1 + int2bytes(ctx.ex.S))
        if M2 != M2ver:
            raise ValueError

        ctx.sessionkey = sessionkey
        ctx.cipher = AESCBC(sessionkey)
        ctx.mackey = mackey

        print "*** Session key is:", repr(sessionkey)
        print "*** MAC key is:", repr(mackey)
        
        ctx.ex.status = 0
        
        return True

    raise ValueError

s, v = ircsrp_generate("alice", "passw")
dave = IRCSRPCtx(True)
dave.users.db["alice"] = (s, v)

dave.username = "dave"
dave.sessionkey = urandom(32)
dave.mackey = urandom(32)
dave.cipher = AESCBC(dave.sessionkey)

alice = IRCSRPCtx()
alice.username = "alice"
alice.password = "passw"


