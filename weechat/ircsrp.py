#!/usr/bin/env python
## ircsrp.py - A weechat IRCSRP script
##
## Copyright (c) 2011, TC Hough <tchough@tchough.com>
## Copyright (c) 2009, Bjorn Edstrom <be@bjrn.se>
##  
## Permission to use, copy, modify, and/or distribute this software for any
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

## Here's a bunch of documentation for this Weechat script!
##
##

## Settings will be put here!

## ircsrp imports
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

# Weechat script imports
import pickle
import re
import os.path
import sys
from optparse import OptionParser

# We use the fcntl module to lock the roster on platforms that support it.
try:
    import fcntl
except ImportError:
    pass

#####
## ircsrp2.py code:
#####

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

    #print "*** Sent by username:", username
    #print "*** Sent at time:", time.ctime(timestamp)

    plain = plain[4+2+usernamelen:]

    # New key?
    if plain.startswith('\xffKEY'):
        new = plain[4:]
        if not len(new) == 32 + 32:
            raise MalformedError
        ctx.sessionkey = new[:32]
        ctx.mackey = new[32:]
        ctx.cipher = AESCBC(ctx.sessionkey)
        #print "*** Session key changed to:", repr(ctx.sessionkey)
        #print "*** MAC key changed to:", repr(ctx.mackey)
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

        #print "*** Session key is:", repr(sessionkey)
        #print "*** MAC key is:", repr(mackey)
        
        ctx.ex.status = 0
        
        return True

    raise ValueError


#####
# Weechat script stuff
#####

# Script globals
ircsrp_cmd_hook = None              # Hook for /ircsrp command
ircsrp_general_hooks = []           # Other hooks that are needed as long as ircsrp is active
ircsrp_temp_hooks = {}              # Temporary hooks
ircsrp_buffers_contexts = {}        # Dict of buffer:WeeSRPCTX()
weechat_dir = None                  # Will hold weechat's config dir

# Default settings
settings = {
        # Interval (in ms) between rekeys (6 hours)
        'channel_default.dave.rekey_interval':str(6*60*60*1000),

        # Interval (in ms) between roster re-reads (0 = never)
        'channel_default.dave.reread_roster_interval':'0',

        # Waiting room channel ('' for disabled)
        #'channel_default.dave.waiting_room':'',

        # Post auth mode set (default is +v ; '' for disabled)
        'channel_default.dave.post_auth.user_default.mode':'+v'
}

class WeeSRPCTX(object):

    def __init__(self, ctx=None, hooks=None, dave_nick=None,
            roster_file_name=None, waiting_room=None):
        """
        ctx -- IRCSRPCtx
        hooks -- dict of hooks
        dave_nick -- nick of dave (if not dave)
        roster_file_name -- file name of roster (if dave)
        waiting_room -- buffer for waiting room (if waiting room mode on)
        """
        self.ctx = ctx 
        if hooks is None:
            self.hooks = {}
        else:
            self.hooks = hooks
        self.dave_nick = dave_nick
        self.roster_file_name = roster_file_name
        self.waiting_room = waiting_room
        self.encrypted_room = None # for waiting room mode, defined on invite
        self.encrypted_room_buffer_name = None # for waiting room mode, defined on join 

    def __repr__(self):
        return '<WeeSRPCTX: ctx=%s, hooks=%s, dave_nick=%s>' % (str(self.ctx),
                str(self.hooks), str(self.dave_nick))

def ircsrp_cmd_cb(data, buffer, args):
    """
    Callback for weechat ircsrp command hook.
    """
    args = args.split()
    if len(args) > 0 and args[0] == 'dave-enable':
        # dave-enable command
        # this logic is obtuse, i should replace it with something cleaner.
        wr_buffer = None
        if len(args) > 1:
            roster = args[1]
            if len(args) > 2:
                # channel arg is provided
                channel = args[2]
                buffer = w.buffer_search('irc', channel)
                if buffer == '':
                    # couldn't find channel
                    w.prnt('', w.prefix('error') + 'Unable to locate channel; have you joined?')
                    return w.WEECHAT_RC_ERROR
                if len(args) > 3:
                    # waiting room arg is provided
                    wr_channel = args[3]
                    wr_buffer = w.buffer_search('irc', wr_channel)
                    if wr_buffer == '':
                        # couldn't find channel
                        w.prnt('', w.prefix('error') + 'Unable to locate channel; have you joined?')
                        return w.WEECHAT_RC_ERROR
            else:
                # channel is implied from current buffer
                buffer = w.current_buffer()
            # attempt to enable dave mode w/ roster on buffer
            return ircsrp_dave_enable(buffer, roster, wr_buffer=wr_buffer)
        else:
            # no roster listed; barf
            w.prnt('', w.prefix('error') + 'Which roster should be used?')
            return w.WEECHAT_RC_ERROR
    elif len(args) > 0 and args[0] == 'dave-disable':
        # dave-disable command
        if len(args) > 1:
            # channel arg is provided
            channel = args[1]
            buffer = w.buffer_search('irc', channel)
            if buffer == '':
                # couldn't find channel
                w.prnt('', w.prefix('error') + 'Unable to locate channel; have you joined?')
                return w.WEECHAT_RC_ERROR
        else:
            # channel arg implied from current buffer
            buffer = w.current_buffer()
        # attempt to disable dave mode on buffer
        return ircsrp_dave_disable(buffer)
    elif len(args) > 0 and args[0] == 'dave-newkey':
        # dave-newkey command
        if len(args) > 1:
            # channel arg is provided
            channel = args[1]
            buffer = w.buffer_search('irc', channel)
            if buffer == '':
                # couldn't find channel
                w.prnt('', w.prefix('error') + 'Unable to locate channel; have you joined?')
                return w.WEECHAT_RC_ERROR
        else:
            # channel arg implied from current buffer
            buffer = w.current_buffer()
        # attempt to rekey buffer
        return ircsrp_dave_newkey(buffer)
    elif len(args) > 0 and args[0] == 'dave-reread-roster':
        # dave-reread-roster command
        if len(args) > 1:
            # channel arg is provided
            channel = args[1]
            buffer = w.buffer_search('irc', channel)
            if buffer == '':
                # couldn't find channel
                w.prnt('', w.prefix('error') + 'Unable to locate channel; have you joined?')
                return w.WEECHAT_RC_ERROR
        else:
            # channel arg implied from current buffer
            buffer = w.current_buffer()
        # attempt to reread roster of buffer
        return ircsrp_dave_reread_roster(buffer)
    elif len(args) > 0 and args[0] == 'auth':
        # auth command - 3 args req'd 1 arg optional
        if len(args) > 3:
            # username, password, dave_nick provided
            username, password, dave_nick = args[1:4]
            if len(args) > 4:
                # channel arg is provided
                channel = args[4]
                buffer = w.buffer_search('irc', channel)
                if buffer == '':
                    # couldn't find channel
                    w.prnt('', w.prefix('error') + 'Unable to locate channel; have you joined?')
                    return w.WEECHAT_RC_ERROR
            else:
                # channel arg implied from current buffer
                buffer = w.current_buffer()
            # attempt to enable ircsrp on buffer w/ dave_nick
            return ircsrp_enable(buffer, username, password, dave_nick, auth_only=True)
        else:
            # not enough args
            w.prnt('', w.prefix('error') + 'Not enough arguments.')
            return w.WEECHAT_RC_ERROR
    elif len(args) > 0 and args[0] == 'enable':
        # enable command - 3 args req'd 1 arg optional
        if len(args) > 3:
            # username, password, dave_nick provided
            username, password, dave_nick = args[1:4]
            if len(args) > 4:
                # channel arg is provided
                channel = args[4]
                buffer = w.buffer_search('irc', channel)
                if buffer == '':
                    # couldn't find channel
                    w.prnt('', w.prefix('error') + 'Unable to locate channel; have you joined?')
                    return w.WEECHAT_RC_ERROR
            else:
                # channel arg implied from current buffer
                buffer = w.current_buffer()
            # attempt to enable ircsrp on buffer w/ dave_nick
            return ircsrp_enable(buffer, username, password, dave_nick)
        else:
            # not enough args
            w.prnt('', w.prefix('error') + 'Not enough arguments.')
            return w.WEECHAT_RC_ERROR
    elif len(args) > 0 and args[0] == 'disable':
        # disable command
        if len(args) > 1:
            # channel arg is provided
            channel = args[1]
            buffer = w.buffer_search('irc', channel)
            if buffer == '':
                # couldn't find channel
                w.prnt('', w.prefix('error') + 'Unable to locate channel; have you joined?')
                return w.WEECHAT_RC_ERROR
        else:
            # channel arg implied from current buffer
            buffer = w.current_buffer()
        # attempt to disable ircsrp on buffer
        return ircsrp_disable(buffer)
    else:
        # unknown command
        w.prnt('', w.prefix('error') + 'Unknown command.')
        return w.WEECHAT_RC_ERROR

    return weechat.WEECHAT_RC_OK

def ircsrp_dave_enable(buffer, roster, wr_buffer=None):
    """
    Enable dave mode using roster on buffer.

    buffer -- channel buffer to enable on
    roster -- roster short name
    wr_buffer -- optional channel buffer for waiting room

    Returns WEECHAT_RC_OK or WEECHAT_RC_ERROR.
    """
    global ircsrp_buffers_contexts
    # Sanity checks:
    #   * buffer is not already enabled
    if ircsrp_on_buffer(buffer):
        w.prnt('', w.prefix('error') + 'IRCSRP already enabled on the specified buffer.')
        return w.WEECHAT_RC_ERROR

    # Unpickle roster (IRCSRPUsers object)
    try:
        users = ircsrp_get_users_from_roster(roster)
    except Exception ,e:
        w.prnt('', w.prefix('error') + 'Error reading roster file: ' + str(e))
        return w.WEECHAT_RC_ERROR
    # Build IRCSRPCtx object (w/ dave param)
    ctx = IRCSRPCtx(dave=True)
    # ctx.users = unpickled IRCSRPUsers object
    ctx.users = users
    # Set an initial key
    # XXX: This should be somewhere else, but where?  I need session key for cipher, but
    # ircsrp rekey methods that set session key require cipher be already set :(
    ctx.sessionkey = os.urandom(32)
    ctx.mackey = os.urandom(32)
    ctx.cipher = AESCBC(ctx.sessionkey)
    # Hook general hooks (if necessary)
    if len(ircsrp_general_hooks) == 0:
        ircsrp_hook_general()

    # Deal with instance independent timer hooks
    hooks = {}
    # Read rekey interval from config
    rekey_interval = int(ircsrp_config_get_channel(buffer, 'dave.rekey_interval'))
    # Hook timer hook (for rekey)
    rekey_hook = w.hook_timer(rekey_interval, 0, 1, 'ircsrp_newkey_cb', buffer)
    hooks['rekey'] = rekey_hook

    # Read roster reread interval from config
    reread_interval = int(ircsrp_config_get_channel(buffer, 'dave.reread_roster_interval'))
    if reread_interval != 0: # Make sure it's not disabled
        # Hook timer hook (for rekey)
        reread_hook = w.hook_timer(reread_interval, 0, 1, 'ircsrp_reread_roster_cb', buffer)
        hooks['reread'] = reread_hook

    # add to global ircsrp_buffers_contexts dict
    ircsrp_buffers_contexts[buffer] = WeeSRPCTX(ctx=ctx, hooks=hooks, dave_nick=None,
            roster_file_name=roster, waiting_room=wr_buffer)
    return w.WEECHAT_RC_OK

def ircsrp_dave_disable(buffer):
    """
    Disable dave mode on buffer.

    Returns WEECHAT_RC_OK or WEECHAT_RC_ERROR.
    """
    global ircsrp_buffers_contexts
    # Sanity checks:
    #   * buffer is enabled as dave
    if not ircsrp_on_buffer(buffer, dave=True):
        # Not enabled as dave
        w.prnt('', w.prefix('error') + 'IRCSRP not enabled in dave-mode on the specified buffer.')
        return w.WEECHAT_RC_ERROR

    # Unhook channel specific hook(s)
    hooks = ircsrp_buffers_contexts[buffer].hooks
    for h in hooks:
        w.unhook(hooks[h])
    # remove buffer from global ircsrp_buffers_contexts dict
    del ircsrp_buffers_contexts[buffer]
    
    # If last to be disabled, unhook ircsrp general hooks
    if len(ircsrp_buffers_contexts) < 1:
        ircsrp_unhook_general()
    
    return w.WEECHAT_RC_OK

def ircsrp_dave_newkey(buffer):
    """
    Activates a new key on the specified buffer.

    Returns WEECHAT_RC_OK or WEECHAT_RC_ERROR.
    """
    global ircsrp_buffers_contexts
    # Sanity checks:
    #   * buffer is enabled as dave
    if not ircsrp_on_buffer(buffer, dave=True):
        # Not enabled as dave
        w.prnt('', w.prefix('error') + 'IRCSRP not enabled in dave-mode on the specified buffer.')
        return w.WEECHAT_RC_ERROR

    # Setup timer hook for rekeying if needed:
    # Remove old timer
    hooks = ircsrp_buffers_contexts[buffer].hooks
    if 'rekey' in hooks:
        w.unhook(hooks['rekey'])
        del hooks['rekey']

    # Read rekey interval from config
    rekey_interval = int(ircsrp_config_get_channel(buffer, 'dave.rekey_interval'))
    if rekey_interval != 0:
        # Hook timer hook (for next rekey)
        timer_hook = w.hook_timer(rekey_interval, 0, 1, 'ircsrp_newkey_cb', buffer)
        hooks['rekey'] = timer_hook

    ctx = ircsrp_buffers_contexts[buffer].ctx
    newkey_msg = ircsrp_new_ctx_key(ctx)
    # Get channel name
    channel = w.buffer_get_string(buffer, 'name').split('.')[1] # XXX: hmmm... what if buffer's name gets changed?
    # Send out key message.  :nosrp is added to disable outgoing encryption.
    w.command(buffer, '/quote PRIVMSG %s :nosrp:%s' % (channel, newkey_msg))
    # Get current topic
    current_topic = w.buffer_get_string(buffer, 'title')
    # Change topic XXX: Check if topic is encrypted before changing?
    w.command(buffer, '/topic %s' % current_topic)
    return w.WEECHAT_RC_OK

def ircsrp_dave_reread_roster(buffer):
    """
    Rereads the roster file on the specified buffer.

    Returns WEECHAT_RC_OK or WEECHAT_RC_ERROR.
    """
    global ircsrp_buffers_contexts
    # Sanity checks:
    #   * buffer is enabled as dave
    if not ircsrp_on_buffer(buffer, dave=True):
        # Not enabled as dave
        w.prnt('', w.prefix('error') + 'IRCSRP not enabled in dave-mode on the specified buffer.')
        return w.WEECHAT_RC_ERROR

    # Setup timer hook for rereading if needed:
    # Remove old timer
    hooks = ircsrp_buffers_contexts[buffer].hooks
    if 'reread' in hooks:
        w.unhook(hooks['reread'])
        del hooks['reread']

    # Read reread interval from config
    reread_interval = int(ircsrp_config_get_channel(buffer, 'dave.reread_roster_interval'))
    if reread_interval != 0:
        # Hook timer hook (for next reread)
        timer_hook = w.hook_timer(reread_interval, 0, 1, 'ircsrp_reread_roster_cb', buffer)
        hooks['reread'] = timer_hook

    ctx = ircsrp_buffers_contexts[buffer]
    # Reread roster file
    users = ircsrp_get_users_from_roster(ctx.roster_file_name)
    # Replace users db leaving already underway negotiations intact.
    # XXX: Security implications... if:
    # (1) auth is underway
    # (2) user credentials removed
    # (3) user is authed even though credentials are removed
    # Possible attack: start a stalled auth process in anticipation of revoked credentials.
    # This is not something I'm worrying about right now.
    ctx.ctx.users.db = users.db
    return w.WEECHAT_RC_OK

def ircsrp_enable(buffer, username, password, dave_nick, auth_only=False):
    """
    Enable ircsrp on buffer

    username -- login username
    password -- login password
    dave_nick -- dave's nick, duuuhhh!
    auth_only -- if True, initiate and on success, wait for an invite
                from dave and enable on that channel (don't enable encryption
                and decryption on specified buffer)
    """
    global ircsrp_buffers_contexts
    global ircsrp_general_hooks
    # Sanity checks:
    #   * buffer is not already enabled
    if ircsrp_on_buffer(buffer):
        w.prnt('', w.prefix('error') + 'IRCSRP already enabled on the specified buffer.')
        return w.WEECHAT_RC_ERROR

    # Create context, grab first keyex msg
    ctx = IRCSRPCtx()
    ctx.username = username
    ctx.password = password
    # Clean up dave_nick
    dave_nick = dave_nick.strip().lower()
    
    # If we're doing auth only, the specified buffer is the waiting room.
    # Otherwise, there is no waiting room.
    if auth_only:
        waiting_room = buffer
    else:
        waiting_room = None

    # Add context to global dict (no channel specific hooks needed, hence the [])
    ircsrp_buffers_contexts[buffer] = WeeSRPCTX(ctx=ctx, hooks=None,
                                    waiting_room=waiting_room, dave_nick=dave_nick)
    # Hook general hooks (if necessary)
    if len(ircsrp_general_hooks) == 0:
        ircsrp_hook_general()
    # Send 1st key exchange msg to dave
    key_request = ircsrp_exchange(ctx)
    w.command(buffer, '/quote NOTICE %s :%s' % (dave_nick, key_request))

    return w.WEECHAT_RC_OK

def ircsrp_disable(buffer):
    """
    Disable ircsrp on buffer
    """
    global ircsrp_buffers_contexts
    # Sanity checks:
    #   * buffer is enabled as not-dave
    if not ircsrp_on_buffer(buffer):
        # Not enabled as dave
        w.prnt('', w.prefix('error') + 'IRCSRP not enabled on the specified buffer.')
        return w.WEECHAT_RC_ERROR

    # Unhook channel specific hooks (if any)
    hooks = ircsrp_buffers_contexts[buffer].hooks
    for h in hooks:
        w.unhook(hooks[h])
    
    # Remove context from global dict
    del ircsrp_buffers_contexts[buffer]

    # Unhook general hooks if last
    if len(ircsrp_buffers_contexts) == 0:
        ircsrp_unhook_general()

    return w.WEECHAT_RC_OK

def ircsrp_get_users_from_roster(roster):
    """
    Returns an IRCSRPUsers object from roster string.
    """
    global weechat_dir
    # Find weechat roster dir.  It's weechat_dir/ircsrp/
    roster_dir_path = os.path.join(weechat_dir, 'ircsrp_rosters')
    roster_file_path = os.path.join(roster_dir_path, '%s.roster' % roster)
    if not os.path.isfile(roster_file_path):
        # XXX: choose another exception type?
        raise ValueError('%s does not exist.' % roster_file_path)
    roster_file_obj = open(roster_file_path, 'r')
    try:
        # Check if file locking is supported
        if 'fcntl' in sys.modules:
            # Obtain lock
            fcntl.flock(roster_file_obj, fcntl.LOCK_SH)
        # Attempt to unpickle
        roster_obj = pickle.load(roster_file_obj)
    finally:
        if 'fcntl' in sys.modules:
            # Release lock
            fcntl.flock(roster_file_obj, fcntl.LOCK_UN)
    return roster_obj

def ircsrp_new_ctx_key(ctx):
    """
    Generate a new key and stick it in the given IRCSRPCtx.

    Returns dave's rekey message.
    """
    # Possible fixme: will this raise an exception if mackey='' like it does at first?
    return ctx.set_key(os.urandom(64))

def ircsrp_on_buffer(buffer, dave=False):
    """
    Return bool indicating whether IRCSRP is enabled on buffer

    dave -- if True, bool indicates whether user is dave on buffer
    """
    global ircsrp_buffers_contexts
    if buffer not in ircsrp_buffers_contexts:
        # Not enabled at all
        return False
    elif dave and not hasattr(ircsrp_buffers_contexts[buffer].ctx, 'users'):
        # Dave's not here, man
        return False
    else:
        return True

def ircsrp_hook_general():
    """
    Hook up general ircsrp hooks that are needed as long as its active in at least 1 buffer.
    """
    global ircsrp_general_hooks

    # Modifier hooks
    ircsrp_general_hooks.append(w.hook_modifier('irc_in2_privmsg', 'ircsrp_in_msg_cb', ''))
    ircsrp_general_hooks.append(w.hook_modifier('irc_in2_notice', 'ircsrp_in_msg_cb', ''))
    ircsrp_general_hooks.append(w.hook_modifier('irc_in2_332', 'ircsrp_in_msg_cb', ''))
    ircsrp_general_hooks.append(w.hook_modifier('irc_in2_topic', 'ircsrp_in_msg_cb', ''))
    ircsrp_general_hooks.append(w.hook_modifier('irc_in2_invite', 'ircsrp_in_invite_cb', ''))
    ircsrp_general_hooks.append(w.hook_modifier('irc_out_privmsg', 'ircsrp_out_msg_cb', ''))
    ircsrp_general_hooks.append(w.hook_modifier('irc_out_topic', 'ircsrp_out_msg_cb', ''))

    # Signal hooks
    ircsrp_general_hooks.append(w.hook_signal('buffer_closing', 'ircsrp_buffer_closing_cb', ''))
    ircsrp_general_hooks.append(w.hook_signal('irc_channel_opened', 'ircsrp_irc_channel_opened_cb', ''))

def ircsrp_unhook_general():
    """
    Unhook general ircsrp hooks.
    """
    global ircsrp_general_hooks
    for h in ircsrp_general_hooks:
        w.unhook(h)
    ircsrp_general_hooks = []

def ircsrp_config_get_channel(buffer, option, fallback=True):
    """
    Returns a config setting for a buffer, falling back on the non-channel specific defaults.

    buffer -- buffer to read channel name from
    option -- config option
    fallback -- if False, don't fall back on non-channel specific defaults.
    """
    # Get buffer name
    buffer_name = w.buffer_get_string(buffer, 'name')
    # Try to get channel specific config
    value = w.config_get_plugin('channel_%s.%s' % (buffer_name, option))
    if value == '' and fallback:
        # Try default
        value = w.config_get_plugin('channel_default.%s' % option)
    # No need to check
    return value

def ircsrp_in_msg_cb(data, modifier, modifier_data, strng):
    # XXX: what about nick collisions due to different irc networks?
    match = re.match(r'^:(.*?) (PRIVMSG|NOTICE|TOPIC|332) (.*?) :(.*)$', strng)
    if match:
        sender, cmd, recipients, msg = match.groups()
        orig_msg = msg
        give_sender_badge = False
        global ircsrp_buffers_contexts
        # Decide if message is encrypted, key exchange, or plaintext.
        if msg.startswith('*'): # Possibly encrypted - should we decrypt?
            # recipients could be multiple space delimitted entries.  If so, we'll try the first
            # channel entry in our buffer search.  If no entries look like channels, we'll go
            # ahead and try something before giving up.
            # TODO: report error in that case, maybe?
            for r in recipients.split(' '):
                channel = r
                if r.startswith('#'): break

            # modifier_data = servername for this modifier
            buffer = w.buffer_search('irc', '%s.%s' % (modifier_data, channel))
            if buffer == '':
                # Couldn't find channel buffer, just return.
                return strng
            ctx = None
            if buffer in ircsrp_buffers_contexts and \
                    ircsrp_buffers_contexts[buffer].waiting_room != buffer:
                # Ircsrp is enabled on this channel and it's not the waiting room.
                ctx = ircsrp_buffers_contexts[buffer].ctx # Grab context
            else: # Search contexts for encrypted room (in case we're in waiting room mode)
                for b in ircsrp_buffers_contexts:
                    if ircsrp_buffers_contexts[b].encrypted_room == buffer:
                        ctx = ircsrp_buffers_contexts[b].ctx
                        break
            if ctx is not None:
                try:
                    msg = ircsrp_unpack(ctx, msg)
                    if msg is None:
                        # A session key change just took place.  Print a notice, but don't print a
                        # message.
                        w.prnt('', w.prefix('network') + 'IRCSRP new session key')
                        return ''
                except MalformedError, ValueError:
                    # This is either plaintext or undecryptable with our string.
                    pass
                else:
                    give_sender_badge = True
        elif msg.startswith('+srpa'):
            # Probably key exchange.  Are we expecting a keyexchange from this nick?
            # Dave is always expecting a keyexchange from any nick on one of his encrypted
            # channels.  Others only expect key exchange messages from dave.
            sender_nick = sender.split('!')[0].lower() # Get sender nick
            if msg[5] in ('0','2'):
                # This key exchange notice implies we're dave.  We'll search each ircsrp enabled
                # context until we find one in which we're dave.  Then we'll check to make sure
                # that the sender is on the channel nicklist before we respond.
                for buffer in ircsrp_buffers_contexts:
                    weesrpctx = ircsrp_buffers_contexts[buffer]
                    ctx = weesrpctx.ctx
                    if ctx.isdave: # We're dave.
                        # Verify that sender nick is on the channel (or waiting room)
                        if w.nicklist_search_nick(buffer, '', sender_nick) != '' or \
                            (weesrpctx.waiting_room is not None and
                            (w.nicklist_search_nick(weesrpctx.waiting_room, '',
                                sender_nick) != '')):
                            # Sender resides on encrypted channel or waiting room.  We can
                            # response to this message.
                            
                            # Before we respond, though, if we're in waiting
                            # room mode, we'll check to see if the client is
                            # already in the encrypted room.  If he is, we'll
                            # kick him.  We do this becase the irc invite is
                            # how we communicate the encrypted channel name to
                            # the client - if he's already in the room, we
                            # can't send him that invite.  We also can't assume
                            # that his IRCSRP client is smart enough to figure
                            # out the encrypted room without the invite.
                            if (weesrpctx.waiting_room is not None and
                                    w.nicklist_search_nick(buffer, '', sender_nick) != ''):
                                # We're in waiting room mode and a client is reauthing - kick!
                                w.command(buffer, '/kick %s' % sender_nick)

                            # XXX: This is kind of ugly, but unless I refactor the original IRCSRP
                            # code, it has to be done.  We're taking the user name value from the
                            # SRP exchange object, but it has to be before the exchange has 
                            # been completed because the original code deletes the exchange object
                            # at that time.
                            #
                            # I'll probably refactor those underlying objects at some point. --TC
                            #
                            if msg[5] == '2':
                                srp_user = weesrpctx.ctx.users.others[sender_nick].I
                            else:
                                # If we're on step 0, just leave srp_user undefined.
                                srp_user = None

                            try:
                                # Generate and send response to this keyexchange message.
                                response = ircsrp_exchange(ctx, msg, sender_nick)
                            except MalformedError, ValueError:
                                # This is either unlikely plaintext or bad exchange, pass along.
                                pass
                            else:
                                give_sender_badge = True
                                msg = '*** IRCSRP key exchange ***'
                                # Send response
                                if cmd == 'PRIVMSG':
                                    # Send as private message if received as private message.
                                    w.command(buffer, '/quote PRIVMSG %s :%s' %
                                            (sender_nick, response))
                                else:
                                    w.command(buffer, '/quote NOTICE %s :%s' % (sender_nick, response))
                                # Post auth steps
                                if orig_msg[5] == '2':
                                    if weesrpctx.waiting_room is None:
                                        # We're not in waiting room mode.  The user is authed and
                                        # presumably in the room.  Run user post auth.
                                        ircsrp_post_auth_mode_apply(buffer, sender_nick, srp_user)
                                    else:
                                        # We've got a waiting room and auth success. Invite to
                                        # encrypted room and setup set up post auth hook for when
                                        # they join.
                                        global ircsrp_temp_hooks
                                        w.command(buffer, '/invite %s' % sender_nick)
                                        fully_qualified_channel = w.buffer_get_string(buffer, 'name')
                                        key = "%s@%s@%s" % (srp_user, sender_nick,
                                                                        fully_qualified_channel)
                                        ircsrp_temp_hooks[key] = w.hook_signal("*,irc_in2_join",
                                                                "ircsrp_post_auth_join_cb", key)

                                # Break out of for loop, no sense in checking other contexts.
                                break
            elif msg[5] in ('1','3'):
                # This key exchange notice implies we're not dave.  We'll search through each
                # ircsrp enabled context until we find one that has our sender as dave and has
                # started a key exchange already.
                for buffer in ircsrp_buffers_contexts:
                    ctx = ircsrp_buffers_contexts[buffer].ctx
                    dave_nick = ircsrp_buffers_contexts[buffer].dave_nick
                    if ctx.ex.status != 0 and sender_nick.strip().lower() == dave_nick:
                        # Found the right context
                        try:
                            # Generate and send a response to this key exchange message.
                            response = ircsrp_exchange(ctx, msg)
                        except MalformedError, ValueError:
                            # This is either unlikely plaintext or bad negotiation, pass along as is.
                            pass
                        else:
                            give_sender_badge = True
                            msg = '*** IRCSRP key exchange ***'
                            # Send response (if necessary)
                            if response is not True:
                                if cmd == 'PRIVMSG':
                                    # Send as private message if received as private message.
                                    w.command(buffer, '/quote PRIVMSG %s :%s' %
                                            (sender_nick, response))
                                else:
                                    w.command(buffer, '/quote NOTICE %s :%s' % (sender_nick, response))
                            # Break out of for loop, no sense in checking other contexts.
                            break
            else:
                # Invalid key exchange message, pass it unmodified.
                return strng
        else:
            # Must be plaintext
            return strng

        if give_sender_badge:
            # Add nick badge (euro symbol or anus, depending on latin-1 or latin-9 encoding).
            sender = str('\xA4') + sender
        return ':%s %s %s :%s' % (sender, cmd, recipients, msg)
    else:
        return strng

def ircsrp_in_invite_cb(data, modifier, modifier_data, strng):
    # This callback will examine each invite.  If the invite is from dave on an
    # ircsrp context with a waiting room, the channel's expected buffer name
    # will be added as that context's encryption channel and joined.
    #
    # XXX: nick collisions on multiple irc networks might throw a wrench in this...
    # XXX: this makes more sense as a signal, not a modifier... durrr...
    #
    match = re.match(r'^:(.*?) (INVITE) (.*?) :(.*)$', strng)
    if match:
        sender, cmd, recipients, msg = match.groups()
        global ircsrp_buffers_contexts
        sender_nick = sender.split('!')[0].lower() # Get sender nick
        # Determine if sender is one of our daves and if so, get context.
        for buffer in ircsrp_buffers_contexts:
            if ircsrp_buffers_contexts[buffer].dave_nick == sender_nick:
                # We found our dave
                server = w.buffer_get_string(buffer, 'name').split('.')[0]
                ctx = ircsrp_buffers_contexts[buffer]
                # Set the name of the encrypted room in the context.  Another
                # callback will set ctx.encrypted_room with actual buffer ref
                # when the join finishes. (assuming we're not already in it)
                ctx.encrypted_room_buffer_name = '.'.join((server, msg))

                # There used to be a check here to make sure that we weren't
                # already on the channel, but it was removed because (a)
                # servers generally won't accept an invite to a user already on
                # the channel in question and (b) Weechat has no way (that I
                # could figure out) of determining whether or not we're on a
                # channel - sure we can tell if there's a buffer for a channel,
                # but no way to tell if it's a stale parted buffer or not, so
                # the check here didn't work anyways.
                enc_chan_buffer = w.buffer_search('irc', '%s.%s' % (server, msg))
                if enc_chan_buffer != '':
                    # There's a stale buffer here.  We need to destroy it
                    # before joining, otherwise the irc_channel_opened callback
                    # won't ever get called.  For some reason, the callback
                    # doesn't work if there's a stale parted channel buffer
                    # around.  Since I can't figure out a way to test for that
                    # condition, killing the buffer is the only choice left.
                    w.buffer_close(enc_chan_buffer)

                w.command(buffer, '/join ' + msg) # join the channel

    return strng

def ircsrp_irc_channel_opened_cb(data, signal, signal_data):
    # This callback gets executed whenever the irc channel join signal
    # occurs. It examines each SRP context to see if we're joining an
    # encrypted room in response to an invite from Dave.  If so, encryption
    # functionality is enabled by giving the WeeSRPCTX object a buffer
    # pointer.
    buffer = signal_data
    buffer_name = w.buffer_get_string(buffer, 'name')
    global ircsrp_buffers_contexts
    for b in ircsrp_buffers_contexts:
        if ircsrp_buffers_contexts[b].encrypted_room_buffer_name == buffer_name:
            # We are joining the right room; set the buffer pointer to enable
            # encryption properly.
            ctx = ircsrp_buffers_contexts[b]
            ctx.encrypted_room = buffer
            break
    return w.WEECHAT_RC_OK

def ircsrp_out_msg_cb(data, modifier, modifier_data, strng):
    # :nosrp is a special tag that we might optionally insert into a raw PRIVMSG or TOPIC command.
    # I'm open to less hacky suggestions for how to do this.
    match = re.match(r'^(PRIVMSG|TOPIC) (.*?) (:nosrp)?:(.*)$', strng)
    if match:
        cmd, recipients, nosrp, msg = match.groups()
        # modifier_data = servername for this modifier
        buffer = w.buffer_search('irc', '%s.%s' % (modifier_data, recipients))
        if buffer == '':
            # Couldn't find channel buffer, just return.
            return strng
        ctx = None
        if ((buffer in ircsrp_buffers_contexts) and (nosrp is None) and 
                (ircsrp_buffers_contexts[buffer].waiting_room != buffer)):
            # This is from an ircsrp enabled buffer and it's not a nosrp message
            # or from a waiting room.
            # Ircsrp is enabled on this channel; grab context.
            ctx = ircsrp_buffers_contexts[buffer].ctx
        else:
            for b in ircsrp_buffers_contexts:
                if ircsrp_buffers_contexts[b].encrypted_room == buffer:
                    ctx = ircsrp_buffers_contexts[b].ctx
                    break
        if ctx is not None:
            # Attempt to encrypt message
            try:
                msg = ircsrp_pack(ctx, msg)
            except MalformedError, ValueError:
                # This is either plaintext or undecryptable with our string.  Just pass it through.
                pass
        return '%s %s :%s' % (cmd, recipients, msg)
    else:
        return strng

def ircsrp_buffer_closing_cb(data, signal, signal_data):
    """
    Callback to ensure that ircsrp is disabled on buffers that are dying.
    """
    # data = callback_data (unused)
    # signal = 'buffer_closing'
    # signal_data = buffer
    global ircsrp_buffers_contexts
    
    if signal_data in ircsrp_buffers_contexts:
        ircsrp_disable(signal_data)

    return w.WEECHAT_RC_OK

def ircsrp_newkey_cb(buffer, remaining_calls):
    """
    Callback to rekey
    """
    # XXX: Add some check so we don't rekey unless there's been some activity?
    return ircsrp_dave_newkey(buffer)

def ircsrp_reread_roster_cb(buffer, remaining_calls):
    """
    Callback to reread roster file for a particular buffer
    """
    # Reread the roster (new timer gets added if needed)
    return ircsrp_dave_reread_roster(buffer)

def ircsrp_post_auth_join_cb(data, signal, signal_data):
    # Callback for temporary on_join hook for waiting room post-auth
    global ircsrp_temp_hooks
    nick = w.info_get("irc_nick_from_host", signal_data)
    server = signal.split(",")[0]
    channel = signal_data.split(":")[-1]
    # srp_user@nick@server.#channel => n@s.#c
    srp_user, n, sc = data.split('@')
    s, c = sc.split('.')
    # If channel matches, 
    if nick == n and server == s and channel == c:
        buffer = w.info_get("irc_buffer", "%s,%s" % (server, channel))
        if buffer:
            ircsrp_post_auth_mode_apply(buffer, nick, srp_user)

        # Unhook and delete hook ref
        if data in ircsrp_temp_hooks:
            w.unhook(ircsrp_temp_hooks[data])
            del ircsrp_temp_hooks[data]
    return w.WEECHAT_RC_OK

def ircsrp_post_auth_mode_apply(buffer, nick, srp_user):
    """
    buffer -- buffer to apply mode changes to
    nick -- irc nick of auth'd user
    srp_user -- IRCSRP login user

    This function looks up what post auth mode should be set based on SRP user
    and sets that mode for the user on the current buffer.
    """
    # XXX: Case sensitivity for SRP user?
    #
    # XXX: Don't name any users "default" or they won't be able to get specific post auth
    # config options set!  There needs to be a warning about this
    #
    # First, determine what mode to set.  To do so, we'll examine the following
    # config options and choose the first one that exists:
    #
    # <channel>.dave.post_auth.<srp_user>.mode
    # <channel>.dave.post_auth.user_default.mode
    # channel_default.dave.post_auth.<srp_user>.mode
    # channel_default.dave.post_auth.user_default.mode
    #
    
    modes = ircsrp_config_get_channel(buffer, 'dave.post_auth.user_%s.mode' % srp_user,
                fallback=False) or \
            ircsrp_config_get_channel(buffer, 'dave.post_auth.user_default.mode',
                fallback=False) or \
            w.config_get_plugin('channel_default.dave.post_auth.user_%s.mode' % srp_user) or \
            w.config_get_plugin('channel_default.dave.post_auth.user_default.mode')
    
    # We've got the modes from the config, now we just have to apply the mode (or not
    # if it's blank).
    if modes.strip():
        w.command(buffer, '/mode %s %s' % (modes, nick))

        
#####
# Objects and functions not used when in Weechat script mode.
#####
def run_www_server(options):
    """
    options -- options parsed from command line arguments
    """
    # These imports and class defs are pretty heavy, so we only load them here,
    # when absolutely needed.

    # WWW imports
    import select
    import time
    from threading import Thread, Event
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
    from SocketServer import ThreadingMixIn
    import socket
    import cgi

    # WWW classes
    class WeeSRPWWW(ThreadingMixIn, HTTPServer):
        timeout = 1     # SocketServer.handle_request() blocks for 1 seconds, max

        def __init__(self, roster_file_name, *args, **kwargs):
            HTTPServer.__init__(self, *args, **kwargs)
            self.roster_file_name = roster_file_name
            self.kill_me = Event()

        def serve_until_killed(self):
            while not self.kill_me.isSet():
                self.handle_request()

        def kill(self):
            self.kill_me.set() 

    class WeeSRPWWWReqHandler(BaseHTTPRequestHandler):
        _register_closed_template = """
        <html>
        <head><title>Registration closed</title></head>
        <body>
        <p>Registration is currently closed.</p>
        </body>
        </html>
        """

        _register_open_template = """
        <html>
        <head><title>Account registration</title></head>
        <body>
        <p>Register an account:</p>
        <form action="/register" method="post">
        <label name="username">Username</label>
        <input type="text" name="username" />
        <br />
        <label name="password">Password</label>
        <input type="password" name="password" />
        <br />
        <label name="password_confirmation">Password</label>
        <input type="password" name="password_confirmation" />
        <br />
        <input type="submit" />
        </form>
        </body>
        </html>
        """

        _register_error_template = """
        <html>
        <head><title>Account registration</title></head>
        <body>
        <p style="color: red">Account registration failed: %s</p>
        </body>
        </html>
        """

        _register_success_template = """
        <html>
        <head><title>Account registration</title></head>
        <body>
        <p style="color: green">Account registration succeeded.</p>
        </body>
        </html>
        """

        closed = False

        def do_GET(self):
            # Check path and respond appropriately
            if self.path == '/':
                self._send_page(self._register_open_template)
            else:
                self._redirect_to_root()

        def do_POST(self):
            if self.closed:
                self._redirect_to_root()
            elif self.path == '/register':
                params = self._parse_post_params()
                try:
                    self._attempt_registration(params)
                except ValueError, e:
                    self._send_page(self._register_error_template % str(e))
                else:
                    self._send_page(self._register_success_template)
            else:
                self.send_response(404)
                self.end_headers()

        def _attempt_registration(self, params):
            """
            Raises exception if unsuccessful.
            """
            # Sanity check params
            if False in map(params.__contains__,
                    ['username', 'password', 'password_confirmation']):
                # The above condition is true if any of the parameters are missing.
                raise ValueError('registration parameters missing.')
            elif params['password'][0] != params['password_confirmation'][0]:
                # passwords didn't match
                raise ValueError('passwords must match.')
            # At this point, we're all good as long as the username isn't taken.

            # This is a strange try/except clause.  The story is this: old
            # versions of python didn't support try/except/finally clauses,
            # only try/finally clauses.  try/excepts had to be nested inside of
            # try/finally to get the intended effect.  I'm aiming for that.
            # Woo woo!
            try:
                try:
                    # Load up the roster
                    roster_file = open(self.server.roster_file_name, 'r')
                    # Check if file locking is supported
                    if 'fcntl' in sys.modules:
                        # Obtain lock
                        fcntl.flock(roster_file, fcntl.LOCK_EX)
                    # Attempt to unpickle
                    roster_obj = pickle.load(roster_file)
                except Exception, e:
                    # Couldn't unpickle (or something)
                    raise ValueError("couldn't open roster: " + str(e))
                # Roster is open, lock is held
                if params['username'][0] in roster_obj.db:
                    raise ValueError('username already exists')
                try:
                    # Create the account!
                    s, v = ircsrp_generate(params['username'][0], params['password'][0])
                except Exception, e:
                    # Couldn't generate credentials
                    raise ValueError("couldn't generate credentials: " + str(e))
                try:
                    roster_obj.db[params['username'][0]] = (s, v)
                    roster_file.close()
                    roster_file = open(self.server.roster_file_name, 'w')
                    roster_file.write(pickle.dumps(roster_obj))
                    # Success!
                except Exception, e:
                    raise ValueError("couldn't record roster: " + str(e))
            finally:
                if 'fcntl' in sys.modules:
                    # Release lock
                    fcntl.flock(roster_file, fcntl.LOCK_UN)
        
        def _redirect_to_root(self):
            self.send_response(301)
            self.send_header("Location", "/")
            self.end_headers()
        
        def _send_page(self, page):
            # Response/headers
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            # Send page
            self.wfile.write(page)

        def _parse_post_params(self):
            # parse parms
            ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
            if ctype == 'multipart/form-data':
                post_params = cgi.parse_multipart(self.rfile, pdict)
            elif ctype == 'application/x-www-form-urlencoded':
                length = int(self.headers.getheader('content-length'))
                post_params = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
            else:
                post_params = {}

            return post_params


    # Ok, imports and definitions are out of the way, start the web server!
    httpd = WeeSRPWWW(options.www_roster, (options.interface, options.port),WeeSRPWWWReqHandler)
    httpd_thread = Thread(target=httpd.serve_until_killed)
    httpd_thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print "Killing web server..."
        httpd.kill()
        sys.exit(0)

def main(argv=sys.argv):
    # This is the main function if not running as a Weechat script.
    parser = OptionParser()
    # Options we'll need: roster, port, interface
    parser.add_option('-w', '--www', action='store', dest='www_roster',
            help='Enable registration web server on this roster')
    parser.add_option('-p', '--port', action='store', dest='port', type='int',
            default=8888, help='Port to run web server on (default: 8888)')
    parser.add_option('-i', '--interface', action='store', dest='interface',
            default='127.0.0.1', help='Interface to run web server on (default: 127.0.0.1) (0.0.0.0 for all)')
    options, argv = parser.parse_args(argv)
    
    # Verify options
    if not options.www_roster:
        parser.error('nothing to do.')
    elif not os.path.isfile(options.www_roster):
        parser.error('cannot find specified roster')
    elif options.port > 65535 or options.port < 0:
        parser.error('invalid port')

    # Options are verified.
    print "Starting web server..."
    run_www_server(options)

    sys.exit(0)


# Weechat registration - I'd put this all in a function, but weechat doesn't like that.
if __name__ == '__main__':
    try:
        import weechat as w
    except ImportError:
        # We're not under Weechat, act like an executable program.
        main()
        # We're expecting main() to call sys.exit(), but if not...
        sys.exit(1)

    # Register this script
    w.register('ircsrp', 'TC Hough', '0.01', 'ISCL', 'ircsrp', '', '')

    # Register command hook
    ircsrp_cmd_hook = w.hook_command('ircsrp', 'ircsrp management',
        '[dave-enable roster [[channel] [waiting_room_channel]]] | '
        '[dave-disable [channel]] | '
        '[dave-newkey [channel]] | '
        '[dave-reread-roster [channel]] | '
        '[enable username password dave_nick [channel]] | '
        '[disable [channel]]', '',
        'dave-enable roster [%(irc_server_channels)] [%(irc_server_channels)] ||'
        'dave-disable [%(irc_server_channels)] ||'
        'dave-newkey [%(irc_server_channels)] ||'
        'dave-reread-roster [%(irc_server_channels)] ||'
        'enable username password %(irc_server_nicks) [%(irc_server_channels)] ||'
        'disable [%(irc_server_channels)]',
        'ircsrp_cmd_cb', '')

    # Get weechat dir
    weechat_dir = w.info_get("weechat_dir","")

    # Init config params
    for option, default_value in settings.items():
        if w.config_get_plugin(option) == "":
            w.config_set_plugin(option, default_value)


