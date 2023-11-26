#!/usr/bin/env python3
import json

import requests

# Name of the cookie
COOKIE = "session"
MAC_SIZE = 4
def mh5(x):
    state = 0

    x = x + b"\x80"
    x = x + (MAC_SIZE - (len(x) % MAC_SIZE)) * b"\x00"
    # Split into chunks
    print((MAC_SIZE - (len(x) % MAC_SIZE)))
    for j in range(0, len(x), MAC_SIZE):
        state += int.from_bytes(x[j:j + MAC_SIZE], byteorder="big")
        state &= (2 ** 32 - 1)
    return state.to_bytes(length=MAC_SIZE, byteorder="big")

def calc(res, xminus1, xplusone):
    first = res - xplusone
    print(f'RES: {res}, XMINUS: {xminus1}, XPLUS: {xplusone}, first {first + 2**32}')
    if first < 0:
        first += 2**32
    print("AGain: ", first-xminus1)
    if first-xminus1 < 0:
        return first - xminus1 + 2**32
    else:
        return first - xminus1

url = "https://t13.itsec.sec.in.tum.de/950357d650d4fa78"
url = "h"

with requests.Session() as session:
    r = session.get(url)
    original_cookie = session.cookies[COOKIE]
    # ceef72fd7b7d -> Tester Value -> Muss das selbe sein
    # 3c2d80f1 -> Admin Value
    # ceef36cffa8c brauche ich noch

    print(original_cookie.encode())
    #Add some padding or something
    #71a15f40 7b2275223a2022746573746572227d
    #data = mac.hex() + session_json.hex()
    #mac.hex() = 4Bytes ersten 4 Bytes sind mac und danach ist encoded mit Tester
    # Man muss das json objekt so erstellen dass es zu dem selben Mac auswertet und dass es insgesamt der gleiche Hash ist
    # erstelle das richtige mac_p
    # mh5(secretkey + sessiondata) = mac
    # '{"u": "admin", }'
    mac = original_cookie[:8]
    print("Original Mac: ", mac)
    #test_data = b'{"u": "admin", "!~A@!g!a": "\x2e\x28\x3b\x6a"}\x80'
    #test_data = test_data + (MAC_SIZE - (len(test_data) % MAC_SIZE)) * b"\x00"
    test_data = b'{"u": "admin", "c/ta": "\x49\x39\x2c\x2ag"}'
    test_mac = mh5(test_data).hex()
    print("Selfmade mac: ", test_mac)
    testtest = json.loads(bytes.fromhex(test_data.hex()))
    print("Mac: ", mac)
    print(test_data.hex())
    final = str(mac) + str(test_data.hex())
    session.cookies.set(name=COOKIE, value=final, domain="https://t13.itsec.sec.in.tum.de")
    print(f'Values: {session.cookies.values()} and Keys: {session.cookies.keys()}')
    q = session.get(url)
    print(q.text)
