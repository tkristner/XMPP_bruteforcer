# XMPP SCRAM SHA1 "client-proof" password bruteforcer.
#
# You should have a dump of one successful connection (just to avoid bruteforcing a wrong password).
# This is looking like this:
# ---------------------------
#   RAW Messages:
# 1. Client Message 1
# <auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="SCRAM-SHA-1">
#     biwsbj11c2VyLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdM
# </auth>
#
# 2. Server Message 1
# <challenge xmlns="urn:ietf:params:xml:ns:xmpp-sasl">
#     cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0wzcmZjTkhZSlkxWlZ2V1ZzN2oscz1RU1hDUitRNnNlazhiZjkyLGk9NDA5Ng==
# </challenge>
#
# 3. Client Message 2
# <response xmlns="urn:ietf:params:xml:ns:xmpp-sasl">
#     Yz1iaXdzLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdMM3JmY05IWUpZMVpWdldWczdqLHA9djBYOHYzQnoyVDBDSkdiSlF5RjBYK0hJNFRzPQ==
# </response>
#
# 4. Server Message 2
# <success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
#     dj1ybUY5cHFWOFM3c3VBb1pXamE0ZEpSa0ZzS1E9
# </success>
# ---------------------------
# SASL Messages:
# 1. Client Message 1
# n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
#
# 2. Server Message 1
# r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096
#
# 3. Client Message 2
# c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
#
# 4. Server Message 2
# v=rmF9pqV8S7suAoZWja4dJRkFsKQ=
# ---------------------------
#
# You'll need tp provide ("prefix") "min pass length" "max pass length" "client messsage 1 (without start 'n,,')" "server message 1" "client proof to match"
#
# Launch like:
# xmpp_bruteforcer.py 1 6 n=user,r=fyko+d2lbbFgONRv9qkxdawL r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096 v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
# xmpp_bruteforcer.py --prefix pass 1 6 n=user,r=fyko+d2lbbFgONRv9qkxdawL r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096 v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
#
# Author: Thomas KRISTNER
# Date: November 2020

import argparse
import hashlib
import hmac
import re
from passlib.hash import scram
import base64
import itertools


# PBKDF2-SHA-1
def salted_password(password: str, salt: str, iteration: int):
    hex_salt = base64.b64decode(salt).hex()
    bytes_salt = bytes.fromhex(hex_salt)
    salted_pass_hex = scram.derive_digest(password, bytes_salt, iteration, "sha-1")
    # print('salted_password:',salted_pass_hex.hex())
    return salted_pass_hex


# HMAC-SHA-1
def client_key(salt_p: bytes):
    digest = hmac.new(salt_p, bytes("Client Key", encoding='utf8'), hashlib.sha1).digest()
    # print('client_key:', digest.hex())
    return digest


# SHA-1
def stored_key(c_key: bytes):
    h = hashlib.sha1()
    h.update(c_key)
    digest = h.digest()
    # print('stored_key:', digest.hex())
    return digest


# concatenation
def auth_message(client_message_1: str, server_message_1: str):
    server_nonce = re.search('(r=.+?),', server_message_1).group(1)
    auth_m = client_message_1 + "," + server_message_1 + ",c=biws," + str(server_nonce)
    # print('auth_message:', auth_m)
    return auth_m


# HMAC-SHA-1
def client_signature(auth_m: str, sto_key: bytes, encoding='utf8'):
    digest = hmac.new(sto_key, auth_m.encode(encoding), hashlib.sha1).digest()
    # print('client_signature:', digest.hex())
    return digest


# XOR
def client_proof(c_key: bytes, c_sig: bytes):
    c_proof = bytearray()
    for c_key, c_sig in zip(c_key, c_sig):
        c_proof.append(c_key ^ c_sig)
    # print('client_proof:', base64.b64encode(c_proof))
    return base64.b64encode(c_proof)


def bruteforce(prefix: str, chr_min: int, chr_max: int, salt: str, iteration: int, client1: str, server1: str,
               c_proof: bytes):
    chrs = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-+_!?$#@=.,;'
    for i in range(chr_min, chr_max + 1):
        for j in itertools.product(chrs, repeat=i):
            suffix = ''.join(j)
            password_to_test = prefix + suffix
            # print(password_to_test)
            salted = salted_password(password_to_test, salt, iteration)
            ckey = client_key(salted)
            stokey = stored_key(ckey)
            authm = auth_message(client1, server1)
            csig = client_signature(authm, stokey)
            cproof = client_proof(ckey, csig)
            if cproof == c_proof:
                print('Match !:', cproof)
                print(prefix + suffix)
                quit()
            else:
                pass


if __name__ == '__main__':
    # Parsing args
    parser = argparse.ArgumentParser(description='XMPP SCRAM SHA1 Password bruteforcer')
    parser.add_argument('--prefix', type=str, default='', help='Prefix for password generation')
    parser.add_argument('min', type=int, help='min of pw length')
    parser.add_argument('max', type=int, help='max of pw length')
    parser.add_argument('cm_1', type=str, help='client_message_1 like "n=user,r=fyko+d2lbbFgONRv9qkxdawL"')
    parser.add_argument('sm_1', type=str, help='server_messsage_1 like "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"')
    parser.add_argument('c_proof', type=str, help='client proof like "b\'v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=\'"')
    args = parser.parse_args()
    # Let's GO
    s_salt = re.search('s=(\S+),', args.sm_1).group(1)
    s_iter = re.search('i=(\d+)', args.sm_1).group(1)
    # print(args.prefix, '..', args.min, '..', args.max, '..', s_salt, '..', int(s_iter), '..', args.cm_1, '..', args.sm_1, '..', args.c_proof.encode())
    bruteforce(args.prefix, args.min, args.max, s_salt, int(s_iter), args.cm_1, args.sm_1, args.c_proof.encode())
