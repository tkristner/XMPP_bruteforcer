# XMPP_Brut

XMPP SCRAM SHA1 "client-proof" password bruteforcer.

You should have a dump of one successful connection to extract info needed.

This is looking like this:

---------------------------
  RAW Messages:
1. Client Message 1
<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="SCRAM-SHA-1">
    biwsbj11c2VyLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdM
</auth>

2. Server Message 1
<challenge xmlns="urn:ietf:params:xml:ns:xmpp-sasl">
    cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0wzcmZjTkhZSlkxWlZ2V1ZzN2oscz1RU1hDUitRNnNlazhiZjkyLGk9NDA5Ng==
</challenge>

3. Client Message 2
<response xmlns="urn:ietf:params:xml:ns:xmpp-sasl">
    Yz1iaXdzLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdMM3JmY05IWUpZMVpWdldWczdqLHA9djBYOHYzQnoyVDBDSkdiSlF5RjBYK0hJNFRzPQ==
</response>

4. Server Message 2
<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
    dj1ybUY5cHFWOFM3c3VBb1pXamE0ZEpSa0ZzS1E9
</success>

---------------------------

SASL Messages:

1. Client Message 1
n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL

2. Server Message 1
r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096

3. Client Message 2
c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=

4. Server Message 2
v=rmF9pqV8S7suAoZWja4dJRkFsKQ=

---------------------------

You have to provide ("prefix") "min pass length" "max pass length" "client messsage 1 (without start 'n,,')" "server message 1" "client proof to match"

Launch like:

without a password prefix:

xmpp_bruteforcer.py 1 6 n=user,r=fyko+d2lbbFgONRv9qkxdawL r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096 v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=

with a password prefix:

xmpp_bruteforcer.py --prefix pass 1 6 n=user,r=fyko+d2lbbFgONRv9qkxdawL r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096 v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
